import os
import subprocess
import time
import socket
import pytest
import tempfile
import threading

@pytest.fixture(scope="session")
def setup_env():
    print("Building wgtunnel...")
    subprocess.run(["make"], cwd="..", check=True)
    wgtunnel_bin = os.path.abspath("../wgtunnel")
    
    print("Starting docker-compose...")
    subprocess.run(["docker", "compose", "up", "-d", "--build"], check=True)
    
    # Get container name
    container_name = subprocess.run(
        ["docker", "compose", "ps", "-q", "wg-server"], 
        capture_output=True, text=True, check=True
    ).stdout.strip()
    
    # Wait for ready
    print("Waiting for WireGuard server to start...")
    ready = False
    for _ in range(15):
        logs = subprocess.run(["docker", "logs", container_name], capture_output=True, text=True).stdout
        if "ready" in logs:
            ready = True
            break
        time.sleep(1)
    
    if not ready:
        subprocess.run(["docker", "compose", "down", "-v"])
        raise Exception("WireGuard server failed to start or did not output 'ready'")
        
    print("Extracting keys...")
    import base64
    server_pub = subprocess.run(["docker", "exec", container_name, "cat", "/etc/wireguard/server_pub"], capture_output=True, text=True).stdout.strip()
    client_priv = subprocess.run(["docker", "exec", container_name, "cat", "/etc/wireguard/client_priv"], capture_output=True, text=True).stdout.strip()
    
    server_pub_hex = base64.b64decode(server_pub).hex()
    client_priv_hex = base64.b64decode(client_priv).hex()
    
    conf_content = f"""private_key={client_priv_hex}
public_key={server_pub_hex}
endpoint=127.0.0.1:51820
allowed_ip=10.1.1.1/32
persistent_keepalive_interval=25
"""
    fd, conf_path = tempfile.mkstemp(suffix=".conf", prefix="wg_")
    with os.fdopen(fd, 'w') as f:
        f.write(conf_content)
        
    yield {
        "bin": wgtunnel_bin,
        "conf": conf_path,
        "container": container_name
    }
    
    print("Tearing down environment...")
    os.unlink(conf_path)
    subprocess.run(["docker", "compose", "down", "-v", "--remove-orphans"])

def test_local_forward_tcp(setup_env):
    env = setup_env
    # docker container listens on 10.1.1.1:8080 and echos
    socat_proc = subprocess.Popen(
        ["docker", "exec", env["container"], "socat", "TCP-LISTEN:8080,fork,reuseaddr", "EXEC:cat"]
    )
    time.sleep(1) # wait for socat to bind
    
    tunnel_proc = subprocess.Popen([
        env["bin"], "--config", env["conf"], "--local", "10.1.1.2",
        "-L", "127.0.0.1:9090:10.1.1.1:8080:tcp"
    ])
    time.sleep(2) # wait for tunnel and wg handshake
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect(("127.0.0.1", 9090))
        s.sendall(b"hello local tcp")
        resp = s.recv(1024)
        assert resp == b"hello local tcp"
        s.close()
    finally:
        tunnel_proc.terminate()
        socat_proc.terminate()
        tunnel_proc.wait()

def test_local_forward_udp(setup_env):
    env = setup_env
    # docker container listens on UDP 10.1.1.1:8081 and echos
    socat_proc = subprocess.Popen(
        ["docker", "exec", env["container"], "socat", "UDP-LISTEN:8081,fork,reuseaddr", "EXEC:cat"]
    )
    time.sleep(1)
    
    tunnel_proc = subprocess.Popen([
        env["bin"], "--config", env["conf"], "--local", "10.1.1.2",
        "-L", "127.0.0.1:9091:10.1.1.1:8081:udp"
    ])
    time.sleep(2)
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)
        s.sendto(b"hello local udp", ("127.0.0.1", 9091))
        resp, _ = s.recvfrom(1024)
        assert resp == b"hello local udp"
        s.close()
    finally:
        tunnel_proc.terminate()
        socat_proc.terminate()
        tunnel_proc.wait()

# Helper thread for remote forward tests
def host_tcp_echo_server(port, stop_event):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(1)
    s.settimeout(0.5)
    while not stop_event.is_set():
        try:
            conn, _ = s.accept()
            conn.settimeout(0.5)
            data = conn.recv(1024)
            if data:
                conn.sendall(data)
            conn.close()
        except socket.timeout:
            continue
    s.close()

def host_udp_echo_server(port, stop_event):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", port))
    s.settimeout(0.5)
    while not stop_event.is_set():
        try:
            data, addr = s.recvfrom(1024)
            s.sendto(data, addr)
        except socket.timeout:
            continue
    s.close()

def test_remote_forward_tcp(setup_env):
    env = setup_env
    stop_event = threading.Event()
    echo_thread = threading.Thread(target=host_tcp_echo_server, args=(9092, stop_event))
    echo_thread.start()
    
    tunnel_proc = subprocess.Popen([
        env["bin"], "--config", env["conf"], "--local", "10.1.1.2",
        "-R", "8082:127.0.0.1:9092:tcp"
    ])
    time.sleep(2)
    
    try:
        # Client in docker connects to 10.1.1.2:8082 over WireGuard
        res = subprocess.run(
            ["docker", "exec", env["container"], "sh", "-c", "echo 'hello remote tcp' | socat -T 2 - TCP:10.1.1.2:8082"],
            capture_output=True, text=True, timeout=5
        )
        assert "hello remote tcp" in res.stdout
    finally:
        stop_event.set()
        tunnel_proc.terminate()
        tunnel_proc.wait()
        echo_thread.join()

def test_remote_forward_udp(setup_env):
    env = setup_env
    stop_event = threading.Event()
    echo_thread = threading.Thread(target=host_udp_echo_server, args=(9093, stop_event))
    echo_thread.start()
    
    tunnel_proc = subprocess.Popen([
        env["bin"], "--config", env["conf"], "--local", "10.1.1.2",
        "-R", "8083:127.0.0.1:9093:udp"
    ])
    time.sleep(2)
    
    try:
        res = subprocess.run(
            ["docker", "exec", env["container"], "sh", "-c", "echo 'hello remote udp' | socat -T 2 - UDP:10.1.1.2:8083"],
            capture_output=True, text=True, timeout=5
        )
        assert "hello remote udp" in res.stdout
    finally:
        stop_event.set()
        tunnel_proc.terminate()
        tunnel_proc.wait()
        echo_thread.join()

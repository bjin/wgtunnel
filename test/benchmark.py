import os
import subprocess
import time
import tempfile
import json
import base64

def run_cmd(cmd, **kwargs):
    return subprocess.run(cmd, capture_output=True, text=True, **kwargs)

def setup():
    print("Building wgtunnel...")
    run_cmd(["make"], cwd="..", check=True)
    print("Starting docker compose...")
    run_cmd(["docker", "compose", "up", "-d", "--build"], check=True)
    
    container_name = run_cmd(["docker", "compose", "ps", "-q", "wg-server"]).stdout.strip()
    
    print("Waiting for WireGuard server to start...")
    ready = False
    for _ in range(15):
        logs = run_cmd(["docker", "logs", container_name]).stdout
        if "ready" in logs:
            ready = True
            break
        time.sleep(1)
        
    if not ready:
        run_cmd(["docker", "compose", "down", "-v"])
        raise Exception("WireGuard server failed to start")
        
    server_pub = run_cmd(["docker", "exec", container_name, "cat", "/etc/wireguard/server_pub"]).stdout.strip()
    client_priv = run_cmd(["docker", "exec", container_name, "cat", "/etc/wireguard/client_priv"]).stdout.strip()
    
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
        
    return os.path.abspath("../wgtunnel"), conf_path, container_name

def parse_iperf3_json(output, is_udp=False):
    try:
        data = json.loads(output)
        if "end" in data:
            if is_udp:
                # UDP output format
                sent_bps = data["end"]["sum_sent"]["bits_per_second"]
                recv_bps = data["end"]["sum_received"]["bits_per_second"]
                lost_percent = data["end"]["sum_received"]["lost_percent"]
                
                return {
                    "sent_bps": sent_bps,
                    "recv_bps": recv_bps,
                    "lost_percent": lost_percent
                }
            else:
                if "sum_sent" in data["end"] and "sum_received" in data["end"]:
                    sent_bps = data["end"]["sum_sent"]["bits_per_second"]
                    recv_bps = data["end"]["sum_received"]["bits_per_second"]
                    return max(sent_bps, recv_bps)
                elif "sum" in data["end"]:
                    return data["end"]["sum"]["bits_per_second"]
    except Exception as e:
        print(f"Error parsing json: {e}")
        pass
    print(f"DEBUG: Iperf3 output was: {output}")
    if is_udp:
        return {"sent_bps": 0, "recv_bps": 0, "lost_percent": 100}
    return 0

def format_mbps(bps):
    return f"{bps / 1_000_000:.2f} Mbps"

def run_test_L(bin_path, conf_path, container, proto, tcp_baseline_bps=0):
    is_udp = (proto == 'udp')
    print(f"Running {proto.upper()} -L test...")
    
    # Server in container
    s_cmd = ["docker", "exec", "-d", container, "iperf3", "-s", "-p", "5201"]
    subprocess.run(s_cmd)
    time.sleep(1)
    
    tunnel_args = [
        bin_path, "--config", conf_path, "--local", "10.1.1.2",
        "-L", f"127.0.0.1:9090:10.1.1.1:5201:{proto}"
    ]
    if is_udp:
        # iperf3 requires a TCP control channel even for UDP tests
        tunnel_args.extend(["-L", "127.0.0.1:9090:10.1.1.1:5201:tcp"])
        
    tunnel_proc = subprocess.Popen(tunnel_args)
    time.sleep(2)
    
    upload_result = 0 if not is_udp else {"sent_bps": 0, "recv_bps": 0, "lost_percent": 100}
    download_result = 0 if not is_udp else {"sent_bps": 0, "recv_bps": 0, "lost_percent": 100}
    
    try:
        target_bps = int(tcp_baseline_bps * 1.2) if tcp_baseline_bps > 0 else 0
        
        # Measure Upload (Client on host -> Server in container)
        c_cmd_up = ["iperf3", "-c", "127.0.0.1", "-p", "9090", "-t", "10", "-J"]
        if is_udp:
            c_cmd_up.extend(["-u", "-b", f"{target_bps}", "-l", "1380"])
        res_up = run_cmd(c_cmd_up)
        if res_up.returncode != 0:
            print(f"TCP/UDP -L Upload failed: {res_up.stderr}")
        upload_result = parse_iperf3_json(res_up.stdout, is_udp)
        
        # Measure Download (Server in container -> Client on host)
        c_cmd_dn = ["iperf3", "-c", "127.0.0.1", "-p", "9090", "-t", "10", "-R", "-J"]
        if is_udp:
            c_cmd_dn.extend(["-u", "-b", f"{target_bps}", "-l", "1380"])
        res_dn = run_cmd(c_cmd_dn)
        if res_dn.returncode != 0:
            print(f"TCP/UDP -L Download failed: {res_dn.stderr}")
        download_result = parse_iperf3_json(res_dn.stdout, is_udp)
    finally:
        tunnel_proc.terminate()
        tunnel_proc.wait()
        subprocess.run(["docker", "exec", container, "pkill", "iperf3"])
        
    return upload_result, download_result

def run_test_R(bin_path, conf_path, container, proto, tcp_baseline_bps=0):
    is_udp = (proto == 'udp')
    print(f"Running {proto.upper()} -R test...")
    
    # Server on host (since -R forwards from wg network to host)
    server_proc = subprocess.Popen(["iperf3", "-s", "-p", "5201"])
    time.sleep(1)
    
    tunnel_args = [
        bin_path, "--config", conf_path, "--local", "10.1.1.2",
        "-R", f"9090:127.0.0.1:5201:{proto}"
    ]
    if is_udp:
        tunnel_args.extend(["-R", "9090:127.0.0.1:5201:tcp"])
        
    tunnel_proc = subprocess.Popen(tunnel_args)
    time.sleep(2)
    
    upload_result = 0 if not is_udp else {"sent_bps": 0, "recv_bps": 0, "lost_percent": 100}
    download_result = 0 if not is_udp else {"sent_bps": 0, "recv_bps": 0, "lost_percent": 100}
    
    try:
        target_bps = int(tcp_baseline_bps * 1.2) if tcp_baseline_bps > 0 else 0
        
        # Measure Upload (Client in container -> Server on host)
        c_cmd_up = ["docker", "exec", container, "iperf3", "-c", "10.1.1.2", "-p", "9090", "-t", "10", "-J"]
        if is_udp:
            c_cmd_up.extend(["-u", "-b", f"{target_bps}", "-l", "1380"])
        res_up = run_cmd(c_cmd_up)
        if res_up.returncode != 0:
            print(f"TCP/UDP -R Upload failed: {res_up.stderr}")
        upload_result = parse_iperf3_json(res_up.stdout, is_udp)
        
        # Measure Download (Server on host -> Client in container)
        c_cmd_dn = ["docker", "exec", container, "iperf3", "-c", "10.1.1.2", "-p", "9090", "-t", "10", "-R", "-J"]
        if is_udp:
            c_cmd_dn.extend(["-u", "-b", f"{target_bps}", "-l", "1380"])
        res_dn = run_cmd(c_cmd_dn)
        if res_dn.returncode != 0:
            print(f"TCP/UDP -R Download failed: {res_dn.stderr}")
        download_result = parse_iperf3_json(res_dn.stdout, is_udp)
    finally:
        tunnel_proc.terminate()
        server_proc.terminate()
        tunnel_proc.wait()
        server_proc.wait()
        
    return upload_result, download_result

def main():
    bin_path, conf_path, container = setup()
    
    results = []
    try:
        # TCP -L
        tcp_up_l, tcp_dn_l = run_test_L(bin_path, conf_path, container, "tcp")
        results.append(("TCP -L", tcp_dn_l, tcp_up_l, 0, 0))
        
        # TCP -R
        tcp_up_r, tcp_dn_r = run_test_R(bin_path, conf_path, container, "tcp")
        results.append(("TCP -R", tcp_dn_r, tcp_up_r, 0, 0))
        
        # UDP -L
        # tcp_up_l and tcp_dn_l are integers returning from parse_iperf3_json when is_udp=False
        tcp_max_l = max(int(tcp_up_l), int(tcp_dn_l)) if isinstance(tcp_up_l, (int, float)) and isinstance(tcp_dn_l, (int, float)) else 0
        udp_up_l, udp_dn_l = run_test_L(bin_path, conf_path, container, "udp", tcp_max_l)
        # when is_udp=True, run_test_L returns dicts
        results.append(("UDP -L", 
                        udp_dn_l["recv_bps"] if isinstance(udp_dn_l, dict) else 0, 
                        udp_up_l["recv_bps"] if isinstance(udp_up_l, dict) else 0, 
                        udp_dn_l["lost_percent"] if isinstance(udp_dn_l, dict) else 100, 
                        udp_up_l["lost_percent"] if isinstance(udp_up_l, dict) else 100))
        
        # UDP -R
        tcp_max_r = max(int(tcp_up_r), int(tcp_dn_r)) if isinstance(tcp_up_r, (int, float)) and isinstance(tcp_dn_r, (int, float)) else 0
        udp_up_r, udp_dn_r = run_test_R(bin_path, conf_path, container, "udp", tcp_max_r)
        results.append(("UDP -R", 
                        udp_dn_r["recv_bps"] if isinstance(udp_dn_r, dict) else 0, 
                        udp_up_r["recv_bps"] if isinstance(udp_up_r, dict) else 0, 
                        udp_dn_r["lost_percent"] if isinstance(udp_dn_r, dict) else 100, 
                        udp_up_r["lost_percent"] if isinstance(udp_up_r, dict) else 100))
        
    finally:
        os.unlink(conf_path)
        print("Tearing down environment...")
        run_cmd(["docker", "compose", "down", "-v", "--remove-orphans"])
        
    print("\nBenchmark Results:")
    print(f"{'Mode':<10} | {'Download':<40} | {'Upload':<40}")
    print("-" * 95)
    for mode, dn, up, dn_loss, up_loss in results:
        if mode.startswith("TCP"):
            print(f"{mode:<10} | {format_mbps(dn):<40} | {format_mbps(up):<40}")
        else:
            dn_str = f"{format_mbps(dn)} * {100-dn_loss:.1f}% = {format_mbps(dn * (100-dn_loss)/100)}"
            up_str = f"{format_mbps(up)} * {100-up_loss:.1f}% = {format_mbps(up * (100-up_loss)/100)}"
            print(f"{mode:<10} | {dn_str:<40} | {up_str:<40}")

if __name__ == '__main__':
    # run inside test/ directory
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    main()

# wgtunnel

`wgtunnel` is a lightweight, fully user-space WireGuard tunnel tool. It allows you to establish port forwarding (both local to remote, and remote to local) over a virtualized WireGuard network interface without requiring kernel modules or administrative privileges.

The tool spins up an entirely self-contained WireGuard protocol instance. It utilizes `netstack` (from gVisor) to process TCP and UDP packets directly in user-space, bridging them with the physical host network.

## Usage

```text
Usage: wgtunnel --local <ip> [-L [ip:]port:dest:dport[:tcp|udp]]... [-R port:dest:dport[:tcp|udp]]...

Flags:
  -L value
    	Local forward: [ip:]port:dest:dport[:tcp|udp]
  -R value
    	Remote forward: port:dest:dport[:tcp|udp]
  -config string
    	Path to WireGuard configuration file (default "wg.conf")
  -local string
    	Local tunnel IP (e.g., 10.0.0.2)
  -mtu int
    	MTU for wireguard device (default 1408)
  -udp-timeout duration
    	UDP session idle timeout (default 3m0s)
```

`wgtunnel` parses standard SSH-style forwarding flags. You can specify multiple `-L` and `-R` flags to establish several tunnels simultaneously:
*   **`-L` (Local Forward):** Listens on your physical host's network and forwards incoming TCP/UDP traffic through the WireGuard tunnel to a destination IP inside the WireGuard network.
*   **`-R` (Remote Forward):** Listens on the virtual WireGuard network interface and forwards incoming traffic out to a destination IP on your physical host's network.

*Note: If the protocol suffix (`:tcp` or `:udp`) is omitted from the forwarding rule, `tcp` is used by default.*

### Configuration Format

The `-config` file expects the [WireGuard Cross-Platform UAPI format](https://www.wireguard.com/xplatform/). This is slightly different from standard `wg-quick` files.

**Crucially, all keys must be encoded in hexadecimal format, not standard base64.** You can convert standard base64 keys to hex for the configuration file using `xxd`:

```bash
# Generate a new private key and derive its public key, formatting both as hex
priv=$(wg genkey) && echo -e "private_key=$(echo $priv | base64 -d | xxd -p -c 32)\npublic_key=$(echo $priv | wg pubkey | base64 -d | xxd -p -c 32)"
```

Example `wg.conf`:
```ini
private_key=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
public_key=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210
endpoint=127.0.0.1:51820
allowed_ip=10.0.0.1/32
persistent_keepalive_interval=25
```

### Examples

**1. Forward local port 8080 to remote WireGuard IP 10.0.0.1:80 (TCP):**
```bash
wgtunnel -config wg.conf -local 10.0.0.2 -L 8080:10.0.0.1:80:tcp
```

**2. Listen on WireGuard IP 10.0.0.2:9090 and forward to local host database 127.0.0.1:5432:**
```bash
wgtunnel -config wg.conf -local 10.0.0.2 -R 9090:127.0.0.1:5432:tcp
```

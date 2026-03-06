package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// stringSlice allows us to pass multiple flags of the same name (e.g., multiple -L or -R)
type stringSlice []string

func (s *stringSlice) String() string {
	return strings.Join(*s, ", ")
}

func (s *stringSlice) Set(value string) error {
	*s = append(*s, value)
	return nil
}

type TunnelConfig struct {
	Protocol    string // "tcp" or "udp"
	BindIP      string
	BindPort    int
	ForwardAddr string
}

func main() {
	var (
		configFile = flag.String("config", "wg.conf", "Path to WireGuard configuration file")
		localIP    = flag.String("local", "", "Local tunnel IP (e.g., 10.0.0.2)")
		mtu        = flag.Int("mtu", 1408, "MTU for wireguard device")
		udpTimeout = flag.Duration("udp-timeout", 3*time.Minute, "UDP session idle timeout (default: 3m)")
		lFlags     stringSlice
		rFlags     stringSlice
	)
	flag.Var(&lFlags, "L", "Local forward: [ip:]port:dest:dport[:tcp|udp] (listen on host, forward to wg)")
	flag.Var(&rFlags, "R", "Remote forward: port:dest:dport[:tcp|udp] (listen on wg, forward to host)")
	flag.Parse()

	if *localIP == "" || (len(lFlags) == 0 && len(rFlags) == 0) {
		fmt.Println("Usage: wgtunnel --local <ip> [-L [ip:]port:dest:dport[:tcp|udp]]... [-R port:dest:dport[:tcp|udp]]...")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Parse and validate multi-flags
	lConfigs, err := parseForwards(lFlags, false)
	if err != nil {
		log.Fatalf("Error parsing -L flags: %v", err)
	}
	rConfigs, err := parseForwards(rFlags, true)
	if err != nil {
		log.Fatalf("Error parsing -R flags: %v", err)
	}

	// 1. Setup WireGuard
	ipcConfigBytes, err := os.ReadFile(*configFile)
	if err != nil {
		log.Fatalf("Failed to read configuration file '%s': %v", *configFile, err)
	}

	localAddr, err := netip.ParseAddr(*localIP)
	if err != nil {
		log.Fatalf("Invalid local IP: %v", err)
	}

	tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{localAddr},
		[]netip.Addr{netip.MustParseAddr("8.8.8.8")}, // Optional: Default DNS
		*mtu,
	)
	if err != nil {
		log.Fatalf("Failed to create NetTUN: %v", err)
	}

	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, ""))
	if err := dev.IpcSet(string(ipcConfigBytes)); err != nil {
		log.Fatalf("Failed to set IPC config: %v", err)
	}
	if err := dev.Up(); err != nil {
		log.Fatalf("Failed to bring device up: %v", err)
	}

	// 2. Setup Listeners
	var wg sync.WaitGroup
	var listeners []io.Closer

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup -L listeners (Local Host -> WireGuard)
	for _, c := range lConfigs {
		addr := net.JoinHostPort(c.BindIP, strconv.Itoa(c.BindPort))
		if c.Protocol == "tcp" {
			l, err := net.Listen("tcp", addr)
			if err != nil {
				log.Fatalf("Failed to listen TCP on host address %s: %v", addr, err)
			}
			listeners = append(listeners, l)
			wg.Add(1)
			go runTCPListener(ctx, &wg, l, c.ForwardAddr, tnet.Dial, "Local")
		} else {
			udpAddr, err := net.ResolveUDPAddr("udp", addr)
			if err != nil {
				log.Fatalf("Failed to resolve UDP host address %s: %v", addr, err)
			}
			l, err := net.ListenUDP("udp", udpAddr)
			if err != nil {
				log.Fatalf("Failed to listen UDP on host address %s: %v", addr, err)
			}
			listeners = append(listeners, l)
			wg.Add(1)
			go runUDPListener(ctx, &wg, l, c.ForwardAddr, tnet.Dial, "Local", *udpTimeout)
		}
	}

	// Setup -R listeners (WireGuard -> Local Host)
	listenNetIP := net.ParseIP(*localIP)
	for _, c := range rConfigs {
		if c.Protocol == "tcp" {
			addr := &net.TCPAddr{IP: listenNetIP, Port: c.BindPort}
			l, err := tnet.ListenTCP(addr)
			if err != nil {
				log.Fatalf("Failed to listen TCP on wireguard address %s: %v", addr, err)
			}
			listeners = append(listeners, l)
			wg.Add(1)
			go runTCPListener(ctx, &wg, l, c.ForwardAddr, net.Dial, "Remote")
		} else {
			addr := &net.UDPAddr{IP: listenNetIP, Port: c.BindPort}
			l, err := tnet.ListenUDP(addr)
			if err != nil {
				log.Fatalf("Failed to listen UDP on wireguard address %s: %v", addr, err)
			}
			listeners = append(listeners, l)
			wg.Add(1)
			go runUDPListener(ctx, &wg, l, c.ForwardAddr, net.Dial, "Remote", *udpTimeout)
		}
	}

	// 3. Graceful Shutdown handler
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	log.Printf("All tunnels established successfully. Press Ctrl+C to stop.")
	<-sigs
	log.Println("\nShutting down listeners...")

	// SIGNAL THE SHUTDOWN BEFORE CLOSING LISTENERS
	cancel()

	for _, l := range listeners {
		l.Close()
	}
	wg.Wait()
	log.Println("Graceful shutdown complete.")
}

// --- TCP Logic ---

func runTCPListener(ctx context.Context, wg *sync.WaitGroup, listener net.Listener, forwardAddr string, dialFunc func(network, addr string) (net.Conn, error), typ string) {
	defer wg.Done()
	log.Printf("[%s TCP] Listening on %s, forwarding to %s", typ, listener.Addr(), forwardAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return // Context was canceled, exit cleanly.
			default:
				log.Printf("[%s TCP] Accept error: %v", typ, err)
				continue
			}
		}
		go handleTCPConnection(conn, forwardAddr, dialFunc)
	}
}

func handleTCPConnection(inConn net.Conn, forwardAddr string, dialFunc func(network, addr string) (net.Conn, error)) {
	defer inConn.Close()

	outConn, err := dialFunc("tcp", forwardAddr)
	if err != nil {
		log.Printf("Failed to dial TCP forward address %s: %v", forwardAddr, err)
		return
	}
	defer outConn.Close()

	errc := make(chan error, 2)

	copyConn := func(dst, src net.Conn) {
		_, err := io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		errc <- err
	}

	go copyConn(outConn, inConn)
	go copyConn(inConn, outConn)

	<-errc
}

// --- UDP Logic ---

func runUDPListener(ctx context.Context, wg *sync.WaitGroup, listener net.PacketConn, forwardAddr string, dialFunc func(network, addr string) (net.Conn, error), typ string, timeout time.Duration) {
	defer wg.Done()
	log.Printf("[%s UDP] Listening on %s, forwarding to %s", typ, listener.LocalAddr(), forwardAddr)

	var mu sync.Mutex
	sessions := make(map[string]net.Conn)
	buf := make([]byte, 65535)

	for {
		n, clientAddr, err := listener.ReadFrom(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return // Context was canceled, exit cleanly.
			default:
				log.Printf("[%s UDP] ReadFrom error: %v", typ, err)
				continue
			}
		}

		clientKey := clientAddr.String()

		mu.Lock()
		outConn, exists := sessions[clientKey]
		if !exists {
			outConn, err = dialFunc("udp", forwardAddr)
			if err != nil {
				log.Printf("[%s UDP] Failed to dial %s: %v", typ, forwardAddr, err)
				mu.Unlock()
				continue
			}
			sessions[clientKey] = outConn

			go func(c net.Conn, cAddr net.Addr, key string) {
				defer c.Close()
				defer func() {
					mu.Lock()
					if existing, ok := sessions[key]; ok && existing == c {
						delete(sessions, key)
					}
					mu.Unlock()
				}()

				respBuf := make([]byte, 65535)
				for {
					c.SetReadDeadline(time.Now().Add(timeout))
					rn, rerr := c.Read(respBuf)
					if rerr != nil {
						return // Timeout or connection closed
					}
					listener.WriteTo(respBuf[:rn], cAddr)
				}
			}(outConn, clientAddr, clientKey)
		}
		mu.Unlock()

		// Send inbound packet to the forwarded destination
		outConn.Write(buf[:n])
	}
}

// --- Parser ---

func parseForwards(flags []string, isRemote bool) ([]TunnelConfig, error) {
	var configs []TunnelConfig
	usedPorts := make(map[string]bool)

	for _, f := range flags {
		parts := strings.Split(f, ":")
		if len(parts) < 3 {
			return nil, fmt.Errorf("invalid format '%s'", f)
		}

		// Check for optional :tcp or :udp suffix
		proto := "tcp"
		last := strings.ToLower(parts[len(parts)-1])
		if last == "tcp" || last == "udp" {
			proto = last
			parts = parts[:len(parts)-1]
		}

		var ip, portStr, dest, dport string

		if isRemote {
			if len(parts) != 3 {
				return nil, fmt.Errorf("invalid -R format '%s', expected port:dest:dport[:tcp|udp]", f)
			}
			portStr = parts[0]
			dest = parts[1]
			dport = parts[2]
		} else {
			if len(parts) == 3 {
				ip = "0.0.0.0"
				portStr = parts[0]
				dest = parts[1]
				dport = parts[2]
			} else if len(parts) == 4 {
				ip = parts[0]
				portStr = parts[1]
				dest = parts[2]
				dport = parts[3]
			} else {
				return nil, fmt.Errorf("invalid -L format '%s', expected [ip:]port:dest:dport[:tcp|udp]", f)
			}
		}

		// Combine protocol and port to allow binding the same port for TCP and UDP
		portKey := proto + ":" + portStr
		if usedPorts[portKey] {
			flagType := "-L"
			if isRemote {
				flagType = "-R"
			}
			return nil, fmt.Errorf("duplicate port '%s' for protocol '%s' found in %s flags", portStr, proto, flagType)
		}
		usedPorts[portKey] = true

		port, err := strconv.Atoi(portStr)
		if err != nil || port <= 0 || port > 65535 {
			return nil, fmt.Errorf("invalid listen port '%s'", portStr)
		}

		if _, err := strconv.Atoi(dport); err != nil {
			return nil, fmt.Errorf("invalid destination port '%s'", dport)
		}

		configs = append(configs, TunnelConfig{
			Protocol:    proto,
			BindIP:      ip,
			BindPort:    port,
			ForwardAddr: net.JoinHostPort(dest, dport),
		})
	}
	return configs, nil
}

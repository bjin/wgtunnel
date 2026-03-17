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

// flagList allows collecting multiple occurrences of a flag into a slice.
type flagList []string

func (f *flagList) String() string {
	return strings.Join(*f, ", ")
}

func (f *flagList) Set(value string) error {
	*f = append(*f, value)
	return nil
}

type ForwardConfig struct {
	Protocol    string
	BindIP      string
	BindPort    int
	ForwardAddr string
}

func main() {
	var (
		configFile = flag.String("config", "wg.conf", "Path to WireGuard configuration file")
		localIP    = flag.String("local", "", "Local tunnel IP (e.g., 10.0.0.2)")
		mtu        = flag.Int("mtu", 1408, "MTU for wireguard device")
		udpTimeout = flag.Duration("udp-timeout", 3*time.Minute, "UDP session idle timeout")
		lFlags     flagList
		rFlags     flagList
	)
	flag.Var(&lFlags, "L", "Local forward: [ip:]port:dest:dport[:tcp|udp]")
	flag.Var(&rFlags, "R", "Remote forward: port:dest:dport[:tcp|udp]")
	flag.Parse()

	if *localIP == "" || (len(lFlags) == 0 && len(rFlags) == 0) {
		fmt.Println("Usage: wgtunnel --local <ip> [-L [ip:]port:dest:dport[:tcp|udp]]... [-R port:dest:dport[:tcp|udp]]...")
		flag.PrintDefaults()
		os.Exit(1)
	}

	localForwards, err := parseForwards(lFlags, false)
	if err != nil {
		log.Fatalf("Error parsing -L flags: %v", err)
	}
	remoteForwards, err := parseForwards(rFlags, true)
	if err != nil {
		log.Fatalf("Error parsing -R flags: %v", err)
	}

	tunIP, err := netip.ParseAddr(*localIP)
	if err != nil {
		log.Fatalf("Invalid local IP: %v", err)
	}

	// Initialize the WireGuard virtual device in user-space, backed by the gVisor network stack.
	// This maps the provided local IP to a virtual interface and starts the WireGuard protocol.
	tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{tunIP},
		[]netip.Addr{netip.MustParseAddr("8.8.8.8")},
		*mtu,
	)
	if err != nil {
		log.Fatalf("Failed to create NetTUN: %v", err)
	}

	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, ""))
	wgConfig, err := os.ReadFile(*configFile)
	if err != nil {
		log.Fatalf("Failed to read configuration file '%s': %v", *configFile, err)
	}
	if err := dev.IpcSet(string(wgConfig)); err != nil {
		log.Fatalf("Failed to set IPC config: %v", err)
	}
	if err := dev.Up(); err != nil {
		log.Fatalf("Failed to bring device up: %v", err)
	}
	defer dev.Close()

	// Forwarders bridge the physical network and the WireGuard network.
	// "Local" forwarders (-L) listen on the physical host and dial through the WireGuard interface.
	// "Remote" forwarders (-R) listen on the WireGuard interface and dial out to the physical host.
	var wg sync.WaitGroup
	var listeners []io.Closer
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for _, cfg := range localForwards {
		bindAddr := net.JoinHostPort(cfg.BindIP, strconv.Itoa(cfg.BindPort))
		if cfg.Protocol == "tcp" {
			l, err := net.Listen("tcp", bindAddr)
			if err != nil {
				log.Fatalf("Failed to listen TCP on host address %s: %v", bindAddr, err)
			}
			listeners = append(listeners, l)
			wg.Add(1)
			go startTCPForwarder(ctx, &wg, l, cfg.ForwardAddr, tnet.Dial, "Local")
		} else {
			udpAddr, err := net.ResolveUDPAddr("udp", bindAddr)
			if err != nil {
				log.Fatalf("Failed to resolve UDP host address %s: %v", bindAddr, err)
			}
			l, err := net.ListenUDP("udp", udpAddr)
			if err != nil {
				log.Fatalf("Failed to listen UDP on host address %s: %v", bindAddr, err)
			}
			listeners = append(listeners, l)
			wg.Add(1)
			go startUDPForwarder(ctx, &wg, l, cfg.ForwardAddr, tnet.Dial, "Local", *udpTimeout)
		}
	}

	listenNetIP := net.ParseIP(*localIP)
	for _, cfg := range remoteForwards {
		if cfg.Protocol == "tcp" {
			addr := &net.TCPAddr{IP: listenNetIP, Port: cfg.BindPort}
			l, err := tnet.ListenTCP(addr)
			if err != nil {
				log.Fatalf("Failed to listen TCP on wireguard address %s: %v", addr, err)
			}
			listeners = append(listeners, l)
			wg.Add(1)
			go startTCPForwarder(ctx, &wg, l, cfg.ForwardAddr, net.Dial, "Remote")
		} else {
			addr := &net.UDPAddr{IP: listenNetIP, Port: cfg.BindPort}
			l, err := tnet.ListenUDP(addr)
			if err != nil {
				log.Fatalf("Failed to listen UDP on wireguard address %s: %v", addr, err)
			}
			listeners = append(listeners, l)
			wg.Add(1)
			go startUDPForwarder(ctx, &wg, l, cfg.ForwardAddr, net.Dial, "Remote", *udpTimeout)
		}
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	log.Printf("All tunnels established successfully. Press Ctrl+C to stop.")
	<-sigs
	log.Println("\nShutting down listeners...")

	cancel()
	for _, l := range listeners {
		if err := l.Close(); err != nil {
			log.Printf("Warning: failed to close listener: %v", err)
		}
	}
	wg.Wait()
	log.Println("Graceful shutdown complete.")
}

func startTCPForwarder(ctx context.Context, wg *sync.WaitGroup, listener net.Listener, targetAddr string, dialer func(string, string) (net.Conn, error), direction string) {
	defer wg.Done()
	log.Printf("[%s TCP] Listening on %s, forwarding to %s", direction, listener.Addr(), targetAddr)

	for {
		clientConn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				log.Printf("[%s TCP] Accept error: %v", direction, err)
				continue
			}
		}
		go handleTCPConnection(ctx, clientConn, targetAddr, dialer)
	}
}

func handleTCPConnection(ctx context.Context, clientConn net.Conn, targetAddr string, dialer func(string, string) (net.Conn, error)) {
	defer func() { _ = clientConn.Close() }()

	targetConn, err := dialer("tcp", targetAddr)
	if err != nil {
		log.Printf("Failed to dial target %s: %v", targetAddr, err)
		return
	}
	defer func() { _ = targetConn.Close() }()

	// Unblock any stalled io.Copy when the context is canceled (e.g. shutdown)
	// by setting an immediate deadline on both connections. Avoids double-close
	// since clientConn and targetConn are already closed by their defers above.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-ctx.Done()
		now := time.Now()
		_ = clientConn.SetDeadline(now)
		_ = targetConn.SetDeadline(now)
	}()

	errc := make(chan error, 2)

	copyData := func(dst, src net.Conn) {
		_, err := io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		errc <- err
	}

	go copyData(targetConn, clientConn)
	go copyData(clientConn, targetConn)

	<-errc
	<-errc
}

func startUDPForwarder(ctx context.Context, wg *sync.WaitGroup, listener net.PacketConn, targetAddr string, dialer func(string, string) (net.Conn, error), direction string, timeout time.Duration) {
	defer wg.Done()
	log.Printf("[%s UDP] Listening on %s, forwarding to %s", direction, listener.LocalAddr(), targetAddr)

	var mu sync.Mutex
	// sessions maps each client address to a send channel. The goroutine
	// launched per session owns the net.Conn exclusively; the main loop
	// never touches the conn directly, eliminating the race between
	// concurrent writes and the goroutine closing the conn on timeout.
	sessions := make(map[string]chan []byte)
	buffer := make([]byte, 65535)

	for {
		n, clientAddr, err := listener.ReadFrom(buffer)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				log.Printf("[%s UDP] Read error: %v", direction, err)
				continue
			}
		}

		clientKey := clientAddr.String()

		mu.Lock()
		sendChan, exists := sessions[clientKey]
		if !exists {
			targetConn, dialErr := dialer("udp", targetAddr)
			if dialErr != nil {
				log.Printf("[%s UDP] Failed to dial target %s: %v", direction, targetAddr, dialErr)
				mu.Unlock()
				continue
			}
			// Buffered so the main loop is never blocked by a slow session.
			sendChan = make(chan []byte, 1024)
			sessions[clientKey] = sendChan

			go func(conn net.Conn, cAddr net.Addr, key string, ch chan []byte) {
				defer func() { _ = conn.Close() }()
				defer func() {
					mu.Lock()
					// Only delete if the map still points to our channel,
					// not a newer session that reused the same key.
					if sessions[key] == ch {
						delete(sessions, key)
					}
					mu.Unlock()
				}()

				// Forward inbound packets (main loop -> targetConn).
				// Runs as a separate goroutine so it doesn't block the
				// response-reading loop below.
				go func() {
					for pkt := range ch {
						if _, werr := conn.Write(pkt); werr != nil {
							log.Printf("[%s UDP] Write to target %s error: %v", direction, targetAddr, werr)
							_ = conn.Close() // unblock the Read below
							return
						}
					}
				}()

				// Forward response packets (targetConn -> client).
				respBuffer := make([]byte, 65535)
				for {
					_ = conn.SetReadDeadline(time.Now().Add(timeout))
					rn, rerr := conn.Read(respBuffer)
					if rerr != nil {
						return // Timeout or connection closed; defers handle cleanup.
					}
					if _, werr := listener.WriteTo(respBuffer[:rn], cAddr); werr != nil {
						log.Printf("[%s UDP] WriteTo client %s error: %v", direction, cAddr, werr)
					}
				}
			}(targetConn, clientAddr, clientKey, sendChan)
		}
		mu.Unlock()

		// Copy buffer before sending so the next ReadFrom doesn't race with the
		// goroutine draining the channel.
		pkt := make([]byte, n)
		copy(pkt, buffer[:n])
		// Non-blocking send: drop the packet if the session's buffer is full
		// rather than stalling the main read loop for all other clients.
		select {
		case sendChan <- pkt:
		default:
			log.Printf("[%s UDP] Send buffer full for %s, dropping packet", direction, clientKey)
		}
	}
}

func parseForwards(flags []string, isRemote bool) ([]ForwardConfig, error) {
	var configs []ForwardConfig
	usedPorts := make(map[string]bool)

	for _, f := range flags {
		parts := strings.Split(f, ":")
		if len(parts) < 3 {
			return nil, fmt.Errorf("invalid format '%s'", f)
		}

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
			portStr, dest, dport = parts[0], parts[1], parts[2]
		} else {
			if len(parts) == 3 {
				ip, portStr, dest, dport = "0.0.0.0", parts[0], parts[1], parts[2]
			} else if len(parts) == 4 {
				ip, portStr, dest, dport = parts[0], parts[1], parts[2], parts[3]
			} else {
				return nil, fmt.Errorf("invalid -L format '%s', expected [ip:]port:dest:dport[:tcp|udp]", f)
			}
		}

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

		configs = append(configs, ForwardConfig{
			Protocol:    proto,
			BindIP:      ip,
			BindPort:    port,
			ForwardAddr: net.JoinHostPort(dest, dport),
		})
	}
	return configs, nil
}

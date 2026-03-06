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
	BindIP      string
	BindPort    int
	ForwardAddr string
}

func main() {
	var (
		configFile = flag.String("config", "wg.conf", "Path to WireGuard configuration file")
		localIP    = flag.String("local", "", "Local tunnel IP (e.g., 10.0.0.2)")
		mtu        = flag.Int("mtu", 1408, "MTU for wireguard device")
		lFlags     stringSlice
		rFlags     stringSlice
	)
	flag.Var(&lFlags, "L", "Local forward: [ip:]port:dest:dport (listen on host, forward to wireguard)")
	flag.Var(&rFlags, "R", "Remote forward: port:dest:dport (listen on wireguard, forward to host)")
	flag.Parse()

	if *localIP == "" || (len(lFlags) == 0 && len(rFlags) == 0) {
		fmt.Println("Usage: wgtunnel --local <ip> [-L [ip:]port:dest:dport]... [-R port:dest:dport]...")
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
		l, err := net.Listen("tcp", addr)
		if err != nil {
			log.Fatalf("Failed to listen on host address %s: %v", addr, err)
		}
		listeners = append(listeners, l)
		wg.Add(1)
		go runListener(ctx, &wg, l, c.ForwardAddr, tnet.Dial, "Local")
	}

	// Setup -R listeners (WireGuard -> Local Host)
	listenNetIP := net.ParseIP(*localIP)
	for _, c := range rConfigs {
		addr := &net.TCPAddr{IP: listenNetIP, Port: c.BindPort}
		l, err := tnet.ListenTCP(addr)
		if err != nil {
			log.Fatalf("Failed to listen on wireguard address %s: %v", addr, err)
		}
		listeners = append(listeners, l)
		wg.Add(1)
		go runListener(ctx, &wg, l, c.ForwardAddr, net.Dial, "Remote")
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

// runListener loops and accepts incoming connections
func runListener(ctx context.Context, wg *sync.WaitGroup, listener net.Listener, forwardAddr string, dialFunc func(network, addr string) (net.Conn, error), typ string) {
	defer wg.Done()
	log.Printf("[%s] Listening on %s, forwarding to %s", typ, listener.Addr(), forwardAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			// Check if we are intentionally shutting down
			select {
			case <-ctx.Done():
				// Context was canceled, so we expect Accept to fail. Exit cleanly.
				return
			default:
				// If context isn't canceled, it's a real error. Log and retry.
				log.Printf("[%s] Accept error: %v", typ, err)
				continue
			}
		}
		go handleConnection(conn, forwardAddr, dialFunc)
	}
}

// handleConnection handles bidirectional data forwarding cleanly
func handleConnection(inConn net.Conn, forwardAddr string, dialFunc func(network, addr string) (net.Conn, error)) {
	defer inConn.Close()

	outConn, err := dialFunc("tcp", forwardAddr)
	if err != nil {
		log.Printf("Failed to dial forward address %s: %v", forwardAddr, err)
		return
	}
	defer outConn.Close()

	// Channel to signal when one side of the copy finishes
	errc := make(chan error, 2)

	copyConn := func(dst, src net.Conn) {
		_, err := io.Copy(dst, src)
		// Best practice: if the destination connection supports half-close, close the write end.
		// This propagates the EOF to the underlying application.
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		errc <- err
	}

	go copyConn(outConn, inConn)
	go copyConn(inConn, outConn)

	// Block until the first copy routine finishes (e.g. client disconnects or network error)
	// Returning causes the defers to fire, cleanly terminating the other direction.
	<-errc
}

// parseForwards parses -L and -R string formats and validates port uniqueness
func parseForwards(flags []string, isRemote bool) ([]TunnelConfig, error) {
	var configs []TunnelConfig
	usedPorts := make(map[string]bool)

	for _, f := range flags {
		parts := strings.Split(f, ":")
		var ip, portStr, dest, dport string

		if isRemote {
			if len(parts) != 3 {
				return nil, fmt.Errorf("invalid -R format '%s', expected port:dest:dport", f)
			}
			portStr = parts[0]
			dest = parts[1]
			dport = parts[2]
		} else {
			if len(parts) == 3 {
				ip = "0.0.0.0" // Default bind IP
				portStr = parts[0]
				dest = parts[1]
				dport = parts[2]
			} else if len(parts) == 4 {
				ip = parts[0]
				portStr = parts[1]
				dest = parts[2]
				dport = parts[3]
			} else {
				return nil, fmt.Errorf("invalid -L format '%s', expected [ip:]port:dest:dport", f)
			}
		}

		if usedPorts[portStr] {
			flagType := "-L"
			if isRemote {
				flagType = "-R"
			}
			return nil, fmt.Errorf("duplicate port '%s' found in %s flags", portStr, flagType)
		}
		usedPorts[portStr] = true

		port, err := strconv.Atoi(portStr)
		if err != nil || port <= 0 || port > 65535 {
			return nil, fmt.Errorf("invalid listen port '%s'", portStr)
		}

		if _, err := strconv.Atoi(dport); err != nil {
			return nil, fmt.Errorf("invalid destination port '%s'", dport)
		}

		configs = append(configs, TunnelConfig{
			BindIP:      ip, // Empty for -R, to be filled via net.TCPAddr mapping
			BindPort:    port,
			ForwardAddr: net.JoinHostPort(dest, dport),
		})
	}
	return configs, nil
}

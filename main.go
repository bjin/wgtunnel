package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func main() {
	var (
		configFile  = flag.String("config", "wg.conf", "Path to WireGuard configuration file")
		localIP     = flag.String("local", "", "local tunnel IP")
		listenIP    = flag.String("listen", "", "listen IP (if unset or different from local, listen on local device and forward to wireguard device)")
		listenPort  = flag.Int("listen-port", 0, "port to listen on the tunnel IP")
		forwardIP   = flag.String("forward", "", "forward host")
		forwardPort = flag.Int("forward-port", 0, "forward port on the host")
		mtu         = flag.Int("mtu", 1408, "MTU for wireguard device")
	)
	flag.Parse()

	if *localIP == "" || *forwardIP == "" || *listenPort == 0 || *forwardPort == 0 {
		flag.Usage()
		os.Exit(1)
	}

	if *listenIP == "" {
		*listenIP = *localIP
	}

	ipcConfigBytes, err := os.ReadFile(*configFile)
	if err != nil {
		log.Panicf("Failed to read configuration file '%s': %v", *configFile, err)
	}
	ipcConfig := string(ipcConfigBytes)

	localAddr, err := netip.ParseAddr(*localIP)
	if err != nil {
		log.Panic(err)
	}

	tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{localAddr},
		[]netip.Addr{netip.MustParseAddr("8.8.8.8")},
		*mtu,
	)
	if err != nil {
		log.Panic(err)
	}

	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, ""))
	err = dev.IpcSet(ipcConfig)
	if err != nil {
		log.Panic(err)
	}

	err = dev.Up()
	if err != nil {
		log.Panic(err)
	}

	var listener net.Listener
	var dialFunc func(network, addr string) (net.Conn, error)

	if *listenIP == *localIP {
		listenNetIP := net.ParseIP(*listenIP)
		if listenNetIP == nil {
			log.Panic("invalid listen IP")
		}
		listenAddr := &net.TCPAddr{
			IP:   listenNetIP,
			Port: *listenPort,
		}
		listener, err = tnet.ListenTCP(listenAddr)
		if err != nil {
			log.Panic(err)
		}
		dialFunc = net.Dial
	} else {
		listenAddrStr := fmt.Sprintf("%s:%d", *listenIP, *listenPort)
		listener, err = net.Listen("tcp", listenAddrStr)
		if err != nil {
			log.Panic(err)
		}
		dialFunc = tnet.Dial
	}

	log.Printf("Listening on %s:%d, forwarding to %s:%d", *listenIP, *listenPort, *forwardIP, *forwardPort)

	for {
		tunConn, err := listener.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go handleConnection(tunConn, *forwardIP, *forwardPort, dialFunc)
	}
}

func handleConnection(inConn net.Conn, forwardHost string, forwardPort int, dialFunc func(network, addr string) (net.Conn, error)) {
	defer inConn.Close()

	log.Printf("New client connected from %s", inConn.RemoteAddr())

	forwardAddr := fmt.Sprintf("%s:%d", forwardHost, forwardPort)
	outConn, err := dialFunc("tcp", forwardAddr)
	if err != nil {
		log.Printf("failed to dial forward address: %v", err)
		return
	}
	defer outConn.Close()

	go io.Copy(outConn, inConn)
	io.Copy(inConn, outConn)
}

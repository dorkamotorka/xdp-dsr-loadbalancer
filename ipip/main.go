package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf lb lb.c

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

var (
	ifname   string
	backends string
)

func parseIPv4(s string) (uint32, error) {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		return 0, fmt.Errorf("invalid IPv4: %s", s)
	}
	return binary.LittleEndian.Uint32(ip), nil
}

func main() {
	flag.StringVar(&ifname, "i", "lo", "Network interface to attach eBPF programs")
	flag.StringVar(&backends, "backends", "", "IP addressed of backends (separated by ',')")
	flag.Parse()

	if backends == "" {
		fmt.Fprintf(os.Stderr, "Error: missing required backend flags\n\n")
		flag.Usage()
		os.Exit(1)
	}

	// Signal handling / context.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs lbObjects
	if err := loadLbObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	// Example: backends = "10.0.0.2,10.0.0.3,10.0.0.4"
	backendList := strings.Split(backends, ",")
	if len(backendList) != 2 {
		log.Fatalf("For simplicity, this demo expects exactly 2 backend IPs, got %d: %v", len(backendList), backendList)
	}
	for i, backend := range backendList {
		backend = strings.TrimSpace(backend)
		backIP, err := parseIPv4(backend)
		if err != nil {
			log.Fatalf("Invalid backend IP %q: %v", backend, err)
		}

		backEp := lbEndpoint{
			Ip: backIP,
		}

		// Use index i as the map key to store multiple endpoints
		if err := objs.lbMaps.Backends.Put(uint32(i), &backEp); err != nil {
			log.Fatalf("Error adding backend #%d (%s) to eBPF map: %v", i, backend, err)
		}

		log.Printf("Added backend #%d: %s", i, backend)
	}

	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", ifname, err)
	}

	// Attach XDP program to the network interface.
	xdplink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpLoadBalancer,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		log.Fatal("Attaching XDP:", err)
	}
	defer xdplink.Close()
	log.Println("XDP Load Balancer successfully attached and running. Press Enter to exit.")

	// Wait for SIGINT/SIGTERM (Ctrl+C) before exiting
	<-ctx.Done()
	log.Println("Received signal, exiting...")
}

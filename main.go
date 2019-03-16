package main

import (
	"fmt"
	"net"
	"os"
	"encoding/hex"
	"strings"
	"time"
	"github.com/HayatoDoi/arp-scan-X/arp"
	"github.com/HayatoDoi/arp-scan-X/intf"
	flags "github.com/jessevdk/go-flags"
)

//go:generate oui -p main -o oui.go

func main() {
	// opt parse
	var opts struct {
		Version        func()   `short:"v" long:"version" description:"show version"`
		Copyright      func()   `short:"c" long:"copyright" description:"show copyright"`
		InterfaceSlice []string `short:"I" long:"interface" description:"Set interface name"`
		Timeout        int64    `short:"t" long:"timeout" default:"500" description:"Set initial per host timeout\nThis timeout is for the first packet sent to each host.\nsubsequent timeouts are multiplied by the backoff\nfactor which is set with --backoff"`
		Backoff        float64  `short:"b" long:"backoff" default:"1.5" description:"Set timeout backoff factor\nThe per-host timeout is multiplied by this factor                                                     \nafter each timeout. So, if the number of retries\nis 3, the initial per-host timeout is 500ms and the\nbackoff factor is 1.5, then the first timeout will be\n500ms, the second 750ms and the third 1125ms."`
	}

	optsErrMsg := "See the output of arp-scan-X -h for a summary of options."
	opts.Version = func() {
		fmt.Println(versionMSG)
		os.Exit(0)
	}
	opts.Copyright = func() {
		fmt.Println(copyrightMSG)
		os.Exit(0)
	}

	_, err := flags.Parse(&opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", optsErrMsg)
		os.Exit(1)
	}
	// end opt parse

	//get interface name && network address
	var interfaceName string
	var addr *net.IPNet
	if len(opts.InterfaceSlice) == 0 {
		interfaceNames, err := intf.GetAllInterface()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
			os.Exit(1)
		}
		for _, interfaceName_ := range interfaceNames {
			a, _ := intf.GetAddr("v4", interfaceName_)
			err := intf.AddrCheck(a)
			if err == nil {
				interfaceName = interfaceName_
				addr = &a
				break
			}
		}
		if interfaceName == "" {
			fmt.Fprintf(os.Stderr, "Could not find good interface\n")
			os.Exit(1)
		}
	} else if len(opts.InterfaceSlice) == 1 {
		a, _ := intf.GetAddr("v4", opts.InterfaceSlice[0])
		err := intf.AddrCheck(a)
		if err == nil {
			interfaceName = opts.InterfaceSlice[0]
			addr = &a
		} else {
			fmt.Fprintf(os.Stderr, "%s: This insterface is no good interface\n", opts.InterfaceSlice[0])
			os.Exit(1)
		}
	} else if len(opts.InterfaceSlice) == 2 {
		interfaceName = opts.InterfaceSlice[0]
		_, a, err := net.ParseCIDR(opts.InterfaceSlice[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not load ip adress and netmask\n")
			os.Exit(1)
		}
		addr = a
	} else {
		fmt.Fprintf(os.Stderr, "%s\n", optsErrMsg)
		os.Exit(1)
	}

	// make config
	config := arp.Config{
		Interface: interfaceName,
		Timeout:   time.Duration(opts.Timeout) * time.Millisecond,
		Backoff:   opts.Backoff,
		Addr:      addr,
	}
	a, err := arp.New(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error(%s) : %s\n", interfaceName, err)
		os.Exit(1)
	}
	fmt.Printf("Interface: %s, Network range: %v\n", interfaceName, addr)
	arpTables, err := a.Scan()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error(%s) : %s\n", interfaceName, err)
		os.Exit(1)
	}
	for _, arpTable := range arpTables {
		oui := strings.ToUpper(hex.EncodeToString(arpTable.HardwareAddr[:3]))
		organization, ok := MacAndOrganization[oui]
		if ok != true {
			organization = "unknown"
		}
		fmt.Printf("%-15v %-20v %s\n", arpTable.IP, arpTable.HardwareAddr, organization)
	}
}

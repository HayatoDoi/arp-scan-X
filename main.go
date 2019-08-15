package main

import (
	"fmt"
	"os"
	"encoding/hex"
	"strings"
	"time"
	"github.com/HayatoDoi/arp-scan-X/arp"
	"github.com/HayatoDoi/arp-scan-X/syslog"
	flags "github.com/jessevdk/go-flags"
)

//go:generate oui -p main -o oui.go

func main() {
	// opt parse
	var opts struct {
		Version       func()  `short:"v" long:"version" description:"show version"`
		Copyright     func()  `short:"c" long:"copyright" description:"show copyright"`
		InterfaceName string  `short:"I" long:"interface" default:"all" description:"Set interface name"`
		DebugMode     bool    `short:"d" long:"debug" description:"On debug mode"`
		Timeout       int64   `short:"t" long:"timeout" default:"500" description:"Set initial per host timeout\nThis timeout is for the first packet sent to each host.\nsubsequent timeouts are multiplied by the backoff\nfactor which is set with --backoff"`
		Backoff       float64 `short:"b" long:"backoff" default:"1.5" description:"Set timeout backoff factor\nThe per-host timeout is multiplied by this factor                                                     \nafter each timeout. So, if the number of retries\nis 3, the initial per-host timeout is 500ms and the\nbackoff factor is 1.5, then the first timeout will be\n500ms, the second 750ms and the third 1125ms."`
	}


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
		fmt.Fprintf(os.Stderr, "See the output of arp-scan-X -h for a summary of options.\n")
		os.Exit(1)
	}
	// end opt parse

	slog := syslog.New(opts.DebugMode)

	interfaces, err := arp.IfaceToName(opts.InterfaceName)
	if err != nil {
		slog.Errorln("%s", err)

		os.Exit(1)
	}

	success := false
	for _, interface_ := range interfaces {
		// make config
		config := arp.Config{
			Interface: interface_,
			Timeout:   time.Duration(opts.Timeout) * time.Millisecond,
			Backoff:   opts.Backoff,
		}
		a, err := arp.New(config)
		if err != nil {
			slog.Debugln("Error(%s) : %s", interface_, err)
			continue
		}
		slog.Println("Interface: %s, Network range: %v", interface_,a.Addr)
		arpTables, err := a.Scan()
		if err != nil {
			slog.Debugln("Error(%s) : %s", interface_, err)
			continue
		}
		for _, arpTable := range arpTables {
			oui := strings.ToUpper(hex.EncodeToString(arpTable.HardwareAddr[:3]))
			organization, ok := MacAndOrganization[oui]
			if ok != true{
				organization = "unknown"
			}
			slog.Println("%-15v %-20v %s", arpTable.IP, arpTable.HardwareAddr, organization)
		}
		success = true
	}
	if success == false {
		slog.Errorln("No valid ip address configuration.")
		os.Exit(1)
	}
}

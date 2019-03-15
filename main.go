package main

import (
	"fmt"
	"os"
	"encoding/hex"
	"strings"
	"github.com/HayatoDoi/arp-scan-X/arp"
	flags "github.com/jessevdk/go-flags"
)

//go:generate oui -p main -o oui.go

func main() {
	// opt parse
	var opts struct {
		Version       func() `short:"v" long:"version" description:"show version"`
		Copyright     func() `short:"c" long:"copyright" description:"show copyright"`
		InterfaceName string `short:"I" long:"interface" default:"all" description:"Set interface name"`
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

	interfaces, err := arp.IfaceToName(opts.InterfaceName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
	fmt.Println(interfaces)
	for _, interface_ := range interfaces {
		a, err := arp.New(interface_)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
		}
		arpTables, err := a.Scan()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
		}
		for _, arpTable := range arpTables {
			oui := strings.ToUpper(hex.EncodeToString(arpTable.HardwareAddr[:3]))
			organization, ok := MacAndOrganization[oui]
			if ok != true{
				organization = "unknown"
			}
			fmt.Printf("%-15v %-20v %s\n", arpTable.IP, arpTable.HardwareAddr, organization)
		}
	}
}

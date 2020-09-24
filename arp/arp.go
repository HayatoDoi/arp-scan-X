package arp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type Config struct {
	Interface string
	Timeout   time.Duration
	Backoff   float64
}
type arpTable struct {
	IP           net.IP
	HardwareAddr net.HardwareAddr
}

type arpTables []arpTable

type arpStruct struct {
	config  Config
	iface   *net.Interface
	Addr    *net.IPNet
	IfaceID string
}

/*
 * IfaceToName is func....
 * INPUT  : interfaceNames
 *        : ex1, "eth1"
 *        : ex2, "eth1,eth2,eth3"
 *        : ex3, "all"
 * OUTPUT : []string
 *        : ex1, []string{"eth1"}
 *        : ex2, []string{"eth1", "eth2", "eth3"}
 *        : ex3, []string{"eth1", "eth2", "eth3", ... all interface}
 */
func IfaceToName(interfaceNames string) ([]string, error) {
	var r []string
	if interfaceNames == "all" {
		ifaces, err := net.Interfaces()
		if err != nil {
			return r, err
		}
		for _, iface := range ifaces {
			r = append(r, iface.Name)
		}
		return r, nil
	}
	r = strings.Split(interfaceNames, ",")
	for _, interfaceName := range r {
		_, err := net.InterfaceByName(interfaceName)
		if err != nil {
			return r, fmt.Errorf("interface %v: unkown", interfaceName)
		}
	}
	return r, nil
}

/*
 * New is ...
 */
func New(config Config) (arpStruct, error) {
	a := arpStruct{}
	// set config
	a.config = config
	// look for interface.
	iface, err := net.InterfaceByName(config.Interface)
	if err != nil {
		return a, fmt.Errorf("interface %v: unkown", config.Interface)
	}
	a.iface = iface

	// Set interface id.
	a.IfaceID = getInterfaceID(iface.Name)

	// look for IPv4 addresses.
	var addr *net.IPNet
	addrs, err := a.iface.Addrs()
	if err != nil {
		return a, err
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok {
			if ip4 := ipnet.IP.To4(); ip4 != nil {
				addr = &net.IPNet{
					IP:   ip4,
					Mask: ipnet.Mask[len(ipnet.Mask)-4:],
				}
				break
			}
		}
	}
	if len(a.iface.HardwareAddr) == 0 {
		return a, errors.New("Could not obtain MAC address")
	}
	// Sanity-check that the interface has a good address.
	if addr == nil {
		return a, errors.New("Could not find good IP network")
	} else if addr.IP[0] == 127 {
		return a, errors.New("This address is localhost")
	} else if addr.Mask[0] != 0xff || addr.Mask[1] != 0xff {
		return a, errors.New("Netmask is too large")
	}
	a.Addr = addr

	return a, nil
}

// scan scans an individual interface's local network for machines using ARP requests/replies.  scan loops forever, sending packets out regularly.  It returns an error if
// it's ever unable to write a packet.
func (a arpStruct) Scan() (arpTables, error) {
	var at arpTables

	// Open up a pcap handle for packet reads/writes.
	handle, err := pcap.OpenLive(a.IfaceID, 65536, true, pcap.BlockForever)
	if err != nil {
		return at, err
	}
	defer handle.Close()

	stop := make(chan bool)
	go readARP(handle, a.iface, &at, stop)
	defer close(stop)
	// go readARP(handle, a.iface, &at)
	for i := 0; i < 3; i++ {
		if err := writeARP(handle, a.iface, a.Addr); err != nil {
			return at, fmt.Errorf("Could not write packets.\n%v", err)
		}
		time.Sleep(
			time.Duration(
				float64(a.config.Timeout/time.Millisecond)*
					math.Pow(a.config.Backoff, float64(i))) *
				time.Millisecond)
	}
	// We don't know exactly how long it'll take for packets to be
	// sent back to us, but 2 seconds should be more than enough
	// time ;)
	stop <- true
	return at, nil
}

func readARP(handle *pcap.Handle, iface *net.Interface, arpTables *arpTables, stop chan bool) {
	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	in := src.Packets()
	for {
		var packet gopacket.Packet
	pktselect:
		select {
		case <-stop:
			return
		case packet = <-in:
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}
			arp := arpLayer.(*layers.ARP)
			if arp.Operation != layers.ARPReply || bytes.Equal([]byte(iface.HardwareAddr), arp.SourceHwAddress) {
				// This is a packet I sent.
				continue
			}
			// Note:  we might get some packets here that aren't responses to ones we've sent,
			// if for example someone else sends US an ARP request.  Doesn't much matter, though...
			// all information is good information :)
			for _, arpTable := range *arpTables {
				if bytes.Compare(arpTable.HardwareAddr, net.HardwareAddr(arp.SourceHwAddress)) == 0 {
					break pktselect
				}
			}
			*arpTables = append(*arpTables, arpTable{
				IP:           net.IP(arp.SourceProtAddress),
				HardwareAddr: net.HardwareAddr(arp.SourceHwAddress),
			})
		}
	}
}

// writeARP writes an ARP request for each address on our local network to the
// pcap handle.
func writeARP(handle *pcap.Handle, iface *net.Interface, addr *net.IPNet) error {
	// Set up all the layers' fields we can.
	eth := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(iface.HardwareAddr),
		SourceProtAddress: []byte(addr.IP),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
	}
	// Set up buffer and options for serialization.
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	// Send one packet for every address.
	for _, ip := range ips(addr) {
		arp.DstProtAddress = []byte(ip)
		gopacket.SerializeLayers(buf, opts, &eth, &arp)
		if err := handle.WritePacketData(buf.Bytes()); err != nil {
			return err
		}
	}
	return nil
}

// ips is a simple and not very good method for getting all IPv4 addresses from a
// net.IPNet.  It returns all IPs it can over the channel it sends back, closing
// the channel when done.
func ips(n *net.IPNet) (out []net.IP) {
	num := binary.BigEndian.Uint32([]byte(n.IP))
	mask := binary.BigEndian.Uint32([]byte(n.Mask))
	num &= mask
	for mask < 0xffffffff {
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], num)
		out = append(out, net.IP(buf[:]))
		mask++
		num++
	}
	return
}

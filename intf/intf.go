package intf

import (
	"net"
	"fmt"
	// "reflect"
	"errors"
)

func GetAllInterface() (interfaceNames []string, err error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return
	}
	for _, iface := range ifaces {
		interfaceNames = append(interfaceNames, iface.Name)
	}
	return
}

func GetAddr(ipver string, interfaceName string) (v4or6addr net.IPNet, err error){
	// look for IPv4 addresses.
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		err = fmt.Errorf("interface %v: unkown", interfaceName)
		return
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok {
			ip4 := ipnet.IP.To4()
			if ip4 != nil && ipver == "v4" {
				v4or6addr = net.IPNet{
					IP:   ip4,
					Mask: ipnet.Mask[len(ipnet.Mask)-4:],
				}
				return
			}
		}
	}
	return
}

func AddrCheck(addr net.IPNet) error {
	// tmp := net.IPNet{}
	// Sanity-check that the interface has a good address.
	if addr.IP == nil{
		return errors.New("Could not find good IP network")
	} else if addr.IP[0] == 127 {
		return errors.New("This address is localhost")
	} else if addr.Mask[0] != 0xff || addr.Mask[1] != 0xff {
		return errors.New("Netmask is too large")
	}
	return nil
}

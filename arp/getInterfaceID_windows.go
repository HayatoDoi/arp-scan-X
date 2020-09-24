package arp

import (
	"os/exec"
)

func getInterfaceID(interfaceName string) string {
	command := "write-host (get-netadapter| where {$_.Name -eq \"" + interfaceName + "\"}).\"DeviceID\" -NoNewline"
	out, err := exec.Command("powershell", command).Output()
	if err != nil {
		return ""
	}
	return "\\Device\\NPF_" + string(out)
}

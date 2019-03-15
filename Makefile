cc := go build
files := main.go oui.go version.go copyright.go

FW: ${files}
	${cc} -o arp-scan-x ${files}

clean:
	rm arp-scan-x

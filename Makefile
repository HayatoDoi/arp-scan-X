cc := go build
files := main.go oui.go version.go copyright.go
dist := arp-scan-x
ifeq ($(OS),Windows_NT)
	dist := arp-scan-x.exe
endif

FW: ${files}
	${cc} -o $(dist) ${files}

clean:
	rm $(dist)

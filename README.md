# arp-scan-X

arp-scan on X-platform.

| OS | Support |
| --- | --- |
| Linux | o |
| BSD | o |
| MacOS | o |
| windows10 | o |



## Usage

### downloaad command
```command
$ go get github.com/HayatoDoi/arp-scan-x
```

### example
#### Check the devices connected to all interfaces
```command
$ sudo arp-scan-x
Interface: enp0s3, Network range: 10.0.2.15/24
10.0.2.2        52:54:00:12:35:02    unknown
10.0.2.3        52:54:00:12:35:03    unknown
10.0.2.4        52:54:00:12:35:04    unknown
Interface: enp0s8, Network range: 192.168.7.4/24
192.168.7.1     08:00:27:55:b3:75    PCS Systemtechnik GmbH
192.168.7.2     08:00:27:28:b7:1d    PCS Systemtechnik GmbH
192.168.7.3     08:00:27:8c:b2:9e    PCS Systemtechnik GmbH
Interface: enp0s9, Network range: 192.168.56.14/24
192.168.56.1    0a:00:27:00:00:00    unknown
192.168.56.12   08:00:27:50:2f:96    PCS Systemtechnik GmbH
192.168.56.11   08:00:27:53:24:bb    PCS Systemtechnik GmbH
192.168.56.13   08:00:27:70:71:f0    PCS Systemtechnik GmbH
192.168.56.100  08:00:27:f0:75:73    PCS Systemtechnik GmbH
```

#### Check the devices connected enp0s8
```command
$ sudo arp-scan-x -I enp0s8
Interface: enp0s8, Network range: 192.168.7.4/24
192.168.7.2     08:00:27:28:b7:1d    PCS Systemtechnik GmbH
192.168.7.1     08:00:27:55:b3:75    PCS Systemtechnik GmbH
192.168.7.3     08:00:27:8c:b2:9e    PCS Systemtechnik GmbH
```

## Licence
These codes are licensed under MIT.

## Author
[HayatoDoi](https://github.com/HayatoDoi)
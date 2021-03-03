module github.com/kayrus/gof5

require (
	github.com/IBM/netaddr v1.4.0
	github.com/fatih/color v1.10.0
	github.com/howeyc/gopass v0.0.0-20190910152052-7cb4b85ec19c
	github.com/hpcloud/tail v1.0.0
	github.com/kayrus/tuncfg v0.0.0-20210306071952-3921bb103b0a
	github.com/manifoldco/promptui v0.8.0
	github.com/miekg/dns v1.1.35
	github.com/mitchellh/go-homedir v1.1.0
	github.com/pion/dtls/v2 v2.0.8
	github.com/vishvananda/netlink v1.1.0 // indirect
	github.com/zaninime/go-hdlc v1.1.1
	golang.org/x/net v0.0.0-20210224082022-3d97a244fca7
	golang.org/x/sys v0.0.0-20210303074136-134d130e1a04
	golang.zx2c4.com/wireguard v0.0.0-20210225140808-70b7b7158fc9 // indirect
	golang.zx2c4.com/wireguard/windows v0.3.8 // indirect
	gopkg.in/fsnotify.v1 v1.4.7 // indirect
	gopkg.in/tomb.v1 v1.0.0-20141024135613-dd632973f1e7 // indirect
	gopkg.in/yaml.v2 v2.4.0
)

// a fork with a FreeBSD default tun name patch
replace golang.zx2c4.com/wireguard v0.0.0-20210225140808-70b7b7158fc9 => github.com/kayrus/wireguard v0.0.0-20210228102730-04afc3c4c795

// a fork with a Windows convertInterfaceIndexToLUID
replace golang.zx2c4.com/wireguard/windows v0.3.8 => github.com/kayrus/wireguard-windows v0.0.0-20210303100507-540e87897140

go 1.15

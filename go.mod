module github.com/kayrus/gof5

require (
	github.com/IBM/netaddr v1.4.0
	github.com/fatih/color v1.10.0
	github.com/howeyc/gopass v0.0.0-20190910152052-7cb4b85ec19c
	github.com/hpcloud/tail v1.0.0
	github.com/manifoldco/promptui v0.8.0
	github.com/miekg/dns v1.1.35
	github.com/mitchellh/go-homedir v1.1.0
	github.com/pion/dtls/v2 v2.0.4
	github.com/songgao/water v0.0.0-20200317203138-2b4b6d7c09d8
	github.com/vishvananda/netlink v1.1.0
	github.com/zaninime/go-hdlc v1.1.1
	golang.org/x/net v0.0.0-20210224082022-3d97a244fca7
	golang.org/x/sys v0.0.0-20210225014209-683adc9d29d7
	golang.zx2c4.com/wireguard v0.0.0-20210225140808-70b7b7158fc9
	gopkg.in/fsnotify.v1 v1.4.7 // indirect
	gopkg.in/tomb.v1 v1.0.0-20141024135613-dd632973f1e7 // indirect
	gopkg.in/yaml.v2 v2.4.0
)

// a fork with a FreeBSD default tun name patch
replace golang.zx2c4.com/wireguard v0.0.0-20210225140808-70b7b7158fc9 => github.com/kayrus/wireguard v0.0.0-20210228102730-04afc3c4c795

go 1.15

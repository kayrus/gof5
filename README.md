# gof5

## Requirements

* application must be executed under privileged root user

## MacOS

On MacOS run the command below to avoid `cannot be opened because the developer cannot be verified` warning:

```sh
xattr -d com.apple.quarantine ./path/to/gof5_darwin
```

## HOWTO

```sh
# download the latest release
$ sudo gof5 --server server --username username --password token
```

When username and password are not provided, they will be asked if `~/.gof5/cookies.yaml` file doesn't contain previously saved HTTPS session cookies or when the saved session is expired or explicitly terminated (`--close-session`).

Use `--close-session` flag to terminate an HTTPS VPN session on exit. Next startup will require a valid username/password.

Use `--select` to choose a VPN server from the list, known to a current server.

## Configuration

You can define an extra `~/.gof5/config.yaml` file with contents:

```yaml
# DNS proxy listen address, defaults to 127.0.0.1
listenDNS: 127.0.0.1
# TLS certificate check
insecureTLS: false
# Enable IPv6
ipv6: false
# driver specifies which tunnel driver to use.
# supported values are: wireguard, water or pppd.
# wireguard is default.
# pppd requires a pppd library
driver: wireguard
# When pppd driver is used, you can specify a list of extra pppd arguments
PPPdArgs: []
# a list of DNS zones to be resolved by VPN DNS servers
# when empty, every DNS query will be resolved by VPN DNS servers
dns:
- corp.int.
- corp.
# a list of primary DNS servers
# Primary DNS servers. When empty, will be parsed from /etc/resolv.conf
dnsServers:
- 8.8.8.8
- 8.8.4.4
# A list of subnets to be routed via VPN
routes:
- 1.2.3.4
- 1.2.3.5/32
```

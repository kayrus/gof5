# gof5

## Requirements

* an application must be executed under a privileged user

## Linux

If your Linux distribution uses [systemd-resolved](https://www.freedesktop.org/software/systemd/man/systemd-resolved.service.html) or [NetworkManager](https://wiki.gnome.org/Projects/NetworkManager) you can run gof5 without sudo privileges.
You need to adjust the binary capabilities:

```sh
$ sudo setcap cap_net_admin,cap_net_bind_service+ep /path/to/binary/gof5
```

For systemd-resolved you need to adjust PolicyKit Local Authority config, e.g. in Ubuntu:

```sh
$ cd gof5 # changedir to gof5 github repo
$ sudo cp org.freedesktop.resolve1.pkla /var/lib/polkit-1/localauthority/50-local.d/org.freedesktop.resolve1.pkla
$ sudo systemctl restart polkit.service
```

### Per user capabilities

If you want to have more granular restrictions to run gof5, you can allow only particular users to run it.

First of all add an entry before the `none  *` in a `/etc/security/capability.conf` file:

```
cap_net_admin,cap_net_bind_service %username%
```

where a `%username%` is a name of the user, which should get inherited `CAP_NET_ADMIN` and `CAP_NET_BIND_SERVICE` capabilities.

Adjust the binary flags to have inherited capabilities only:

```
$ sudo setcap cap_net_admin,cap_net_bind_service+i /path/to/binary/gof5
```

Check user's capabilities:

```
$ sudo -u %username% capsh --print | awk '/Current/{print $NF}'
cap_net_bind_service,cap_net_admin+i
```

gof5 should be executed using sudo even if you already logged in as this user:

```
$ sudo -u %username% /path/to/binary/gof5
```

## MacOS

On MacOS run the command below to avoid a `cannot be opened because the developer cannot be verified` warning:

```sh
xattr -d com.apple.quarantine ./path/to/gof5_darwin
```

## Windows

Windows version doesn't support `pppd` driver.

## ChromeOS

Developer mode should be enabled, since gof5 requires root privileges.
The binary should be placed inside the `/usr/share/oem` directory. Home directory in ChromeOS doesn't allow to have executables.
You need to restart shill with an option in order to allow tun interface creation: `sudo restart shill BLOCKED_DEVICES=tun0`.
Use the the `driver: pppd` config option if you don't want to restart shill.

## HOWTO

### Build from source

```sh
$ make # gmake in freebsd or mingw make for windows
# or build inside docker (linux version only)
$ make docker
```

### Run

```sh
# download the latest release
$ sudo gof5 --server server --username username --password token
```

Alternatively you can use a session ID, obtained during the web browser authentication (in case, when you have MFA). You can find the session ID by going to the VPN host in a web browser, logging in, and running this JavaScript in Developer Tools:

```js
document.cookie.match(/MRHSession=(.*?); /)[1]
```

Then specify it as an argument:

```sh
$ sudo gof5 --server server --session sessionID
```

When username and password are not provided, they will be asked if `~/.gof5/cookies.yaml` file doesn't contain previously saved HTTPS session cookies or when the saved session is expired or explicitly terminated (`--close-session`).

Use `--close-session` flag to terminate an HTTPS VPN session on exit. Next startup will require a valid username/password.

Use `--select` to choose a VPN server from the list, known to a current server.

Use `--profile-index` to define a custom F5 VPN profile index.

### CA certificate and TLS keypair

Use options below to specify custom TLS parameters:

* `--ca-cert` - path to a custom CA certificate
* `--cert` - path to a user TLS certificate
* `--key` - path to a user TLS key

## Configuration

You can define an extra `~/.gof5/config.yaml` file with contents:

```yaml
# DNS proxy listen address, defaults to 127.0.0.245
# In BSD defaults to 127.0.0.1
# listenDNS: 127.0.0.1
# rewrite /etc/resolv.conf instead of renaming
# Linux only, required in cases when /etc/resolv.conf cannot be renamed
rewriteResolv: false
# experimental DTLSv1.2 support
# F5 BIG-IP server should have enabled DTLSv1.2 support
dtls: false
# TLS certificate check
insecureTLS: false
# Enable IPv6
ipv6: false
# driver specifies which tunnel driver to use.
# supported values are: wireguard or pppd.
# wireguard is default.
# pppd requires a pppd or ppp (in FreeBSD) binary
driver: wireguard
# When pppd driver is used, you can specify a list of extra pppd arguments
PPPdArgs: []
# disableDNS allows to completely disable DNS handling,
# i.e. don't alter system DNS (e.g. /etc/resolv.conf) at all
disableDNS: false
# A list of DNS zones to be resolved by VPN DNS servers
# When empty, every DNS query will be resolved by VPN DNS servers
dns:
- .corp.int.
- .corp.
# for reverse DNS lookup
- .in-addr.arpa.
# A list of subnets to be routed via VPN
# When not set, the routes pushed from F5 will be used
# Use "routes: []", if you don't want gof5 to manage routes at all
routes:
- 1.2.3.4
- 1.2.3.5/32
```

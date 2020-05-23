# gof5

## Requirements

* application must be executed as privileged root user

## HOWTO

```sh
$ make
$ sudo ./bin/gof5 --server server --username username --password token
```

When username and password are not provided, they will be asked if `~/.gof5/cookies.yaml` file doesn't contain previously saved HTTPS session cookies or when the saved session is expired or explicitly terminated (`--close-session`).

Use `--close-session` flag to terminate an HTTPS VPN session on exit. Next startup will require a valid username/password.

A `~/.gof5/config.yaml` file must exist with contents like:

```yaml
# when true, a pppd client will be used
pppd: false
# a list of DNS zones to be resolved by VPN DNS servers
# when empty, every DNS query will be resolved by VPN DNS servers
dns:
- corp.int.
- corp.
# a list of primary DNS servers
# when empty, will be parsed from /etc/resolv.conf
dnsServers:
- 8.8.8.8
- 8.8.4.4
# a list of subnets to be routed via VPN
routes:
- 1.2.3.4
- 1.2.3.5/32
```

## Credits

Based on the https://github.com/rei/f5vpn-client project idea.

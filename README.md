# gof5

## Requirements

* pppd binary must be installed
* application must be executed as privileged root user
* Linux only, pull requests to support MacOS are welcome

## HOWTO

```sh
$ make
$ sudo ./bin/gof5 --server server --username username --password token --debug
```

Username and password will be used only, when `cookies` file doesn't contain previously saved HTTPS session cookies or when the saved session is expired or explicitly terminated (`--close-session`).

Use `--close-session` flag to terminate an HTTPS VPN session on exit. Next startup will require a valid username/password.

A `routes.yaml` file must be placed in the current working directory with contents like:

```yaml
# experimental
# dns enables internal dns proxy, which is not stable enough
# omit "dns" to disable DNS proxy
#dns:
#- corp.int.
#- corp.
routes:
- 1.2.3.4
- 1.2.3.5/32
```

## Credits

Based on the https://github.com/rei/f5vpn-client project idea.

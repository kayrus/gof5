# gof5

```sh
$ make
$ sudo ./bin/gof5 --server server --username username --password token --debug
```

# Work in Progress

The work is still in progress. F5 VPN encapsulates VPN traffic into PPP protocol. More details:
* https://support.f5.com/csp/article/K23207037
* https://support.f5.com/csp/article/K00231525

## TODO

* Veryfy and cut off `0xf5 0x00 bigendian` header
* Pass the rest directly to pppd descriptors

# gof5

```sh
$ make
$ sudo ./bin/gof5 --server server --username username --password token --debug
```

# Work in Progress

The work is still in progress. You can use a [mitmproxy](https://mitmproxy.org/) to analyze the encrypted traffic from the official F5 VPN client:

```sh
# disable certificates check, add "--nocheck" parameter to "f5fpc" CLI
$ iptables -t nat -A PREROUTING -d %F5_VPN_IP% -p tcp --dport 443 -j REDIRECT --to-port 8080
# disable DTLS usage and save the intercepted traffic to a "saved-traffic.mitm" file
$ mitmdump -w saved-traffic.mitm --rawtcp --tcp-hosts %F5_VPN_IP% --mode transparent --replacements ":~s:<tunnel_dtls>1</tunnel_dtls>:<tunnel_dtls>0</tunnel_dtls>" --verbose
```

Then dump the file once mitmdump is done:

```sh
$ mitmdump -r saved-traffic.mitm --flow-detail 3
```

Alternatively the traffic can be analyzed with F5 [Wireshark plugin](https://devcentral.f5.com/s/articles/getting-started-with-the-f5-wireshark-plugin-on-windows).

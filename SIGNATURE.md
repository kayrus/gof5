# Signature

* F5 client requests a token from a server: `/my.logon.php3?outform=xml&client_version=2.0&get_token=1`
* F5 server sends a **token** to a client: `<?xml version="1.0"?><data><token>1</token><version>2.0</version><redirect_url>/my.policy</redirect_url><max_client_data>16384</max_client_data></data>`
* F5 client generates an **XML** with client parameters:

```xml
<agent_info>
  <type>standalone</type>
  <version>2.0</version>
  <platform>Linux</platform>
  <cpu>x64</cpu>
  <javascript>no</javascript>
  <activex>no</activex>
  <plugin>no</plugin>
  <landinguri>/</landinguri>
  <lockedmode>no</lockedmode>
  <hostname>dGVzdA==</hostname> // base64("test")
  <app_id/>
</agent_info>
```

Actual string:

`<agent_info><type>standalone</type><version>2.0</version><platform>Linux</platform><cpu>x64</cpu><javascript>no</javascript><activex>no</activex><plugin>no</plugin><landinguri>/</landinguri><lockedmode>no</lockedmode><hostname>dGVzdA==</hostname><app_id></app_id></agent_info>`

* then client generates some **signature** with 16 bytes size (HMAC-MD5 or a simple MD5) based on **token** and probably client's **useragent**. If **token** is spoofed to `1`, then the signature is `4sY+pQd3zrQ5c2Fl5BwkBg==` (base64([16]byte("e2c63ea50777ceb439736165e41c2406")))
* both **XML** and **signature** are base64 encoded and put into parameters:

`client_data = sprintf(str, "session=%s&device_info=%s&agent_result=%s&token=%s&signature=%s", "", base64(xml), "", token, signature)`

* The **client\_data** string generated above is also base64 encoded and then sent as a POST request to F5 `/my.policy`:

`post_request = sprintf(str, "client_data=%s", base64(client_data))`

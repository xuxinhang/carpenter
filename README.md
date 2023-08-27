
# Carpenter
<small>学点木匠活</small>

这是一个 HTTP / HTTP over TLS 代理服务器，支持：
- 提供 HTTP 代理和 HTTP over TLS 代理，并兼容 HTTP Forward
- 将请求的特定域重定向到指定的IP地址或经 DNS over TLS 或 DNS over UDP 查询得到的地址
- 对特定域抹除或修改TLS SNI字段
- 为不同的域指定不同的出站代理服务器

- 支持 DNS over TLS 实现加密的DNS查询，传统DNS （DNS over UDP） 方式也同样支持。也可以直接为域名指定IP地址。
- 入站支持 HTTP 代理和 HTTP over TLS 代理。出站可以不经代理协议直接发送，也支持转发至外部 HTTP 代理或 HTTP over TLS 代理服务器。
- 可改写或移除 TLS 包的 SNI 字段。
- 为不同的域指定不同的SNI改写、DNS查询服务器或出站方式。
- 纯异步实现网络数据传输。

It's a HTTP / HTTP over TLS proxy server, which supports:
- HTTP proxy and HTTP over TLS proxy
- Redirect the request to specific domains to the given IP address or address queried from DNS over TLS or DNS over UDP server.
- Remove or modify the TLS SNI field for specific domains.
- Assign different outbound proxy servers for specific domains.


## Start

1. Equip your mechine with Rust toolchain.
2. Check the config file `config/core.toml`. Especially make sure the `openssl_path` field has pointed to a valid OpenSSL executable.
3. Run `cargo run --release`.
4. Set your application or OS to use this HTTP proxy.

## Configuration

### **`core.toml`**

```toml
[env]
openssl_path = "openssl"  # The path to OpenSSL binary (ensure added to PATH if using "openssl" directly)


[inbound.normal]                 # Start a proxy server named "normal"
enable = true                    #   enable
listen = "http://0.0.0.0:7890"   #   it's a HTTP proxy server with listen address and port
                                 #   ... only HTTP(http) or HTTP over TLS(https) protocol supported

[inbound.secure]                 # Start a proxy server named "normal"
enable = true                    #   enable
listen = "https://0.0.0.0:7899"  #   it's a HTTP over TLS proxy server with listen address and port
hostname = "localhost"           #   TLS certification require hostname


[outbound.fanq]                    # An outbound proxy destination named "fanq"
enable = true                      #
origin = "https://127.0.0.1:7898"  #   proxy server protocol (only http/https) and address


[log]
log_level = 5             # Log level: 5(debug), 4(info), 3(warn), 2(error), 1(panic)

[dns]                        # DNS querier
cache-expiration = 7200      #   query result caching expiration (in seconds)
load-local-host-file = true  #   whether to load HOST file into query result cache

[dns-server]                      # DNS server protocol and address
normal = "udp://223.5.5.5"        #   DNS over UDP server, named "normal"
secure = "tls://101.101.101.101"  #   DNS over TLS server, named "secure"

```

### **`querier_matcher.txt`**

Format: One rule pre line.
`hostname +action option`

Hostname supports hostname matcher rule, see below.

Supported querier actions and options:
- `+dns secure` Query the current hostname via the given DNS server with name "secure". The DNS server name is assigned in `core.toml`.
- `+to target`  Redirect to the given target (specific hostname or IP address), then act further query if needed.

Example:
```
github.com +dns secure

..wikipedia.org +to 91.198.174.192
*.wiki*.org +to wikipedia.org
```


### **`transformer_matcher.txt`**

Format: One rule pre line.
`hostname:port +transformer options`

Supported transformer and options:
- `+direct` Do not modify tunnel data.
- `+sni` Modify or remove TLS SNI data.
  - modify SNI: `+sni hello.com`
  - remove SNI: `+sni _`
  - use orginal SNI: `+sni *`

Example:
```
*:443 +direct

..steamcommunity.com:443 +sni _
```

### **`outbound_matcher.txt`**

Format: One rule pre line.
`hostname:port +action options`

Supported outbound proxy action:
- `+direct` connect directly, no more proxy
- `+server fanq` connect via the given proxy server named "fanq"

Example:
```
*:0 +direct

*.baidu.com:0 +server fanq
```

### Matcher file rules

Hostname:
- `wikipedia.org` match exactly hostname `wikipedia.org` but no sub-domain
- `*.wikipedia.org` match sub-domains of `wikipedia.org`, such as `upload.wikipedia.org`, but excludes `wikipedia.org` itself.
- `..wikipedia.org` match this domain itself and its sub-domains.

Port:
- `0`: any ports.
- other number: the corresponding port number.

Comments:
- Any contents following hash symbol `#` is viewed as comments.



# Carpenter
<small>学点木匠活</small>

这是一个 HTTP / HTTP over TLS 代理服务器，支持：

- 支持 DNS over TLS 实现加密的DNS查询，也支持传统 DNS over UDP 查询。直接为域名指定 IP 地址亦可。
- 入站支持 HTTP 代理和 HTTP over TLS 代理。
- 出站可以不经代理协议直接发送，也支持转发至外部 HTTP 代理 <!-- 或 HTTP over TLS 代理服务器。 -->
- 可改写或移除指定域名下 TLS 包的 SNI 字段。
- 为不同的域指定不同的SNI改写、DNS查询服务器或出站方式。
- 纯异步实现高性能网络数据传输。

It's an HTTP / HTTP over TLS proxy server, which supports:
- HTTP proxy and HTTP over TLS proxy
- Redirect the request to specific domains to the given IP address or address queried from DNS over TLS or DNS over UDP server.
- Remove or modify the TLS SNI field for specific domains.
- Assign different outbound proxy servers for specific domains.


## Start

1. Equip your machine with Rust toolchain.
2. Check the config file `config/core.toml`. Especially make sure the `openssl_path` field has pointed to a valid OpenSSL executable.
3. Run `cargo run --release`.
4. Set your application or OS to use this HTTP proxy.

## Configuration Example

### **`core.toml`**

```toml
[env]
openssl_path = "openssl"  # The path to OpenSSL binary (ensure added to PATH if using "openssl" directly)


[inbound.normal]                 # Start a proxy server named "normal"
enable = true                    #   enable
listen = "http://0.0.0.0:7890"   #   it's an HTTP proxy server with listen address and port
                                 #   ... only HTTP(http) or HTTP over TLS(https) protocol supported

[inbound.secure]                 # Start a proxy server named "normal"
enable = true                    #   enable
listen = "https://0.0.0.0:7899"  #   it's an HTTP over TLS proxy server with listen address and port
hostname = "localhost"           #   TLS certification requires hostname


[outbound.tor]                     # An outbound proxy destination named "tor"
enable = true                      #
origin = "http://127.0.0.1:8118"   #   proxy server protocol (only http) and address


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
- `+dns secure` Query the current hostname via the given DNS server with name `secure`. The DNS server name is assigned in `core.toml`.
- `+to target`  Redirect to the given target (specific hostname or IP address), then do further querying if needed.

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
- `+sni` Modify or remove TLS SNI fields.
  - assign another SNI: `+sni hello.com`
  - remove SNI: `+sni _`
  - use original SNI: `+sni *`

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
- `+server tor` connect via the given proxy server named "tor"

Example:
```
*:0 +direct

*.baidu.com:0 +server tor
```

### domain matching

Hostname:
- `wikipedia.org` match exactly hostname `wikipedia.org` but no subdomain
- `*.wikipedia.org` match subdomains of `wikipedia.org`, such as `upload.wikipedia.org`, but excludes `wikipedia.org` itself.
- `..wikipedia.org` match this domain itself and its subdomains.

Port:
- `0`: any ports.
- non-zero number: assign as the port number.

Comments:
- Any content prefixed by hash symbol `#` is treated as comments.

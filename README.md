
# Carpenter
<small>学点木匠活</small>

这是一个HTTP隧道代理服务器，支持：
- 将请求的域重定向到通过DoT或DoU查找到的目的地址
- 修改TLS流数据：删除或修改TLS SNI字段

It's a HTTP tunnel proxy server, which supports:
- Redirect the requested domain to the target address queried via DoT or DoU.
- Modify TLS stream data: remove or modify TLS SNI field.



## Start

1. Equip your mechine with Rust toolchain.
2. Check the config file `config/core.toml`. Especially Make sure the `openssl_path` field has pointed to a valid OpenSSL executable. 
3. Run `cargo run --release`.
4. Set your application or OS to use this HTTP tunnel.

## Configuration

**`core.toml`**

```toml
[env]
openssl_path = "openssl"  # The path to OpenSSL binary (ensure added to PATH if using "openssl" directly)

[inbound-http]            # HTTP proxy server
enable = true             #   enable
listen = "0.0.0.0:7890"   #   proxy server listen address and port

[outbound]

[log]
log_level = 5             # Log level: 5(debug), 4(info), 3(warn), 2(error), 1(panic)

[dns]                        # DNS querier
cache-expiration = 7200      #   query result caching expiration (in seconds)
load-local-host-file = true  #   whether to load HOST file into query result cache

[dns-server]                      # DNS server protocol address
normal = "udp://223.5.5.5"        #   support DNS over UDP
secure = "tls://101.101.101.101"  #   support DNS over TLS

```

**`querier_matcher.txt`**

Format: One rule pre line.
`hostname +querier_type option`

Supported querier:
- `+dns provider` Query the current hostname via the given DNS server. The DNS server is assigned in `core.toml`.
- `+to hostname`  Redirect to the given hostname, then do further query if needed.


**`transformer_matcher.txt`**

Format: One rule pre line.
`hostname:port +transformer_type options`

Supported transformer:
- Direct: Do not modify tunnel data.
  - `+direct`
- SNI: modify or remove TLS SNI data.
  - modify SNI: `+sni hello.com`
  - remove SNI: `+sni _`



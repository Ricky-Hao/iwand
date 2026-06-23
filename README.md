# iwand

Panabit iWAN SD-WAN client daemon for Linux/OpenWrt and FreeBSD.

Reverse-engineered from the official `linux_sdwand_x86` binary (glibc-only) and reimplemented as a small C program with zero external dependencies. Compiles to a ~110KB static musl binary that runs on OpenWrt x86_64, or a native FreeBSD amd64 binary.

## Building

```bash
make                        # dynamic build
CC=musl-gcc make static     # static musl build (for OpenWrt)
```

Experimental Go iWAN server:

```bash
go build ./cmd/iwand-server
```

FreeBSD amd64:

```sh
make                        # native FreeBSD build with cc/clang
make install-freebsd        # installs to /usr/local
```

Linux binaries do not run natively on FreeBSD; build on FreeBSD or in a FreeBSD VM.

## Usage

```
iwand [options]
  -f <file>   config file path [default: /etc/iwan/iwan.conf, /usr/local/etc/iwan/iwan.conf on FreeBSD]
  -l <file>   log to file instead of syslog
  -F           run in foreground (log to stderr)
  -v           print version
  -h           print help
```

Logging: foreground → stderr; daemon without `-l` → syslog (`logread | grep iwand`); daemon with `-l` → file.

Send `SIGUSR1` to trigger a reconnect without restarting.

## Configuration

See [`openwrt/iwan.conf.example`](openwrt/iwan.conf.example):

```ini
[iwan0]          # TUN interface name
server=1.2.3.4   # server IP or domain
username=myuser
password=mypass
port=4567
mtu=1400         # 46-1600
encrypt=0        # 0=off, 1=XOR encryption
```

## Experimental Go Server

This repository also includes a simple prototype server for the Go iWAN client in Ricky's sing-box fork. It is intended for local compatibility testing, not production SD-WAN deployment.

Build and run:

```bash
go build -o iwand-server ./cmd/iwand-server
./iwand-server -config server/config.example.json
```

The JSON config defaults to loopback when `listen` is omitted. Keep the default `127.0.0.1:4567` for local tests; binding to a public address should be treated as experimental and not production-grade.

Example schema:

```json
{
  "listen": "127.0.0.1:4567",
  "mtu": 1400,
  "dns": ["1.1.1.1", "8.8.8.8"],
  "users": [
    {
      "username": "alice",
      "password": "change-me-alice",
      "address": "10.20.30.10",
      "allow_encrypt": true
    }
  ]
}
```

Supported server-side protocol subset:

- OPEN / OPENACK / OPENREJ authentication with iWAN MD5 control signatures, TLV total-length parsing, and AES-128 password TLV verification.
- ECHOREQ / ECHORESP and CLOSE with token/session/source validation.
- DATA / DATA_ENC for simple local forwarding between connected configured users by IPv4 destination address; packets without a connected destination are echoed to the sender for smoke tests.
- DATA_ENC XOR compatibility using `MD5(username + password)[0:8]`.

Intentional limitations: no TUN device, no OS route management, no persistent sessions, no IP pool allocation, no IPFRAG reassembly, no segment routing, and no production hardening.

## OpenWrt Deployment

### Option A: Build with OpenWrt SDK

```bash
# In the OpenWrt SDK directory
git clone https://github.com/Ricky-Hao/iwand.git /tmp/iwand
cp -r /tmp/iwand/openwrt/package package/iwand
make package/iwand/compile V=s
```

The `.ipk` will be in `bin/packages/`. Install with `opkg install iwand_*.ipk`.

### Option B: Manual binary install

Download a pre-built binary from [Releases](https://github.com/Ricky-Hao/iwand/releases) or build from source:

```bash
scp iwand root@router:/usr/sbin/
scp openwrt/iwand.init root@router:/etc/init.d/iwand
scp openwrt/iwan.conf.example root@router:/etc/iwan/iwan.conf
ssh root@router chmod 755 /etc/init.d/iwand
ssh root@router vi /etc/iwan/iwan.conf
ssh root@router /etc/init.d/iwand enable
ssh root@router /etc/init.d/iwand start
```

## FreeBSD Deployment

Load the tunnel driver and install the native amd64 build:

```sh
kldload if_tuntap
make install-freebsd
sysrc iwand_enable=YES
service iwand start
```

The rc.d script reads `/usr/local/etc/iwan/iwan.conf` by default. To override it:

```sh
sysrc iwand_config=/path/to/iwan.conf
```

The section name in the config is still the requested TUN interface name, for example `[iwan0]`. On FreeBSD, iwand opens a cloned `tun(4)` device and tries to rename it to that name; if the rename is not permitted, it continues with the kernel-assigned `tunN` name and passes that name to hook scripts.

## Protocol

UDP-based proprietary tunnel protocol with:

- MD5-signed control packets (OPEN, OPENACK, ECHO, CLOSE)
- TLV-encoded authentication (AES-128-ECB encrypted password)
- XOR-encrypted data plane (optional)
- IP fragment reassembly
- Segment routing support (multi-hop, AES decryption)
- Latency measurement via ECHO keepalive

## License

This is a clean-room reimplementation based on protocol analysis. Not affiliated with Panabit.

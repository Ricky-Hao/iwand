# iwand

Panabit iWAN SD-WAN client daemon for Linux/OpenWrt.

Reverse-engineered from the official `linux_sdwand_x86` binary (glibc-only) and reimplemented as a single-file C program with zero external dependencies. Compiles to a ~110KB static musl binary that runs on OpenWrt x86_64.

## Building

```bash
make                        # dynamic build
CC=musl-gcc make static     # static musl build (for OpenWrt)
```

## Usage

```
iwand [options]
  -f <file>   config file path [default: /etc/sdwan/iwan.conf]
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

## OpenWrt Deployment

```bash
# Copy binary
scp iwand root@router:/usr/sbin/

# Copy init script
scp openwrt/iwand.init root@router:/etc/init.d/iwand

# Copy and edit config
scp openwrt/iwan.conf.example root@router:/etc/sdwan/iwan.conf
ssh root@router vi /etc/sdwan/iwan.conf

# Enable and start
ssh root@router /etc/init.d/iwand enable
ssh root@router /etc/init.d/iwand start
```

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

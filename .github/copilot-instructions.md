# Copilot Instructions — iwand

## Build

```bash
make                        # dynamic, current system
CC=musl-gcc make static     # static musl for OpenWrt
make clean
```

## Architecture

Core C program in `src/iwand.c`, with platform TUN backends in `src/tun_linux.c` and `src/tun_freebsd.c`. Single-threaded event loop using `poll()` on TUN fd + UDP fd with 1-second timeout driving the state machine timer.

All crypto is self-contained (embedded MD5, AES-128 ECB encrypt/decrypt, XOR). No external library dependencies.

## Protocol

Packet format: `[type:1][flags:1][token:2][session_id:4]` + optional 16-byte `MD5(header + "mw")` signature + payload.

Key packet types: OPEN (0x13), OPENACK (0x12), DATA (0x14/0x18), ECHO (0x15/0x16), CLOSE (0x17), IPFRAG (0x21), SEGRT (0x27).

TLV format: `[type:1][total_len:1][value:N]` — total_len includes the 2-byte type+len header.

OPEN TLV type 3 = client MTU (not port). Port is read from UDP source header by the server.

## Conventions

- Token and session_id are opaque wire bytes — copied from server OPENACK, never interpreted.
- DATA packets have no MD5 signature and no session validation (matches original behavior).
- XOR key = `MD5(username + password)[0:8]`. Password AES key = `MD5("mw" + username)`.
- State machine: 0=NOT_READY → 2=DNS → 3=IP_READY → 4=AUTH_SENT → 5=ESTABLISHED → 6=CLOSED.
- ECHO payload: timestamp(8) + cur_delay(4) + min_delay(4) + max_delay(4) + pad(4) + route_tag(12).
- Route tag: `"TDR\0"` + `htonl(rt_magic)` + zeros.
- Relative `-f`/`-l` paths are resolved to absolute before `daemonize()` calls `chdir("/")`.

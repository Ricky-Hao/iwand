CC       ?= cc
STRIP    ?= strip
CFLAGS   ?= -O2 -Wall -Wextra -Wno-unused-parameter
LDFLAGS  ?=
TARGET   = iwand
SRC      = src/iwand.c
PREFIX   ?= /usr/local

.PHONY: all static clean install install-freebsd

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $(SRC) $(LDFLAGS)

static: $(SRC)
	$(CC) $(CFLAGS) -static -o $(TARGET) $(SRC) $(LDFLAGS)
	@which $(STRIP) >/dev/null 2>&1 && $(STRIP) $(TARGET) || strip $(TARGET) 2>/dev/null || true

clean:
	rm -f $(TARGET)

install: $(TARGET)
	install -d $(DESTDIR)/usr/sbin
	install -m 0755 $(TARGET) $(DESTDIR)/usr/sbin/
	install -d $(DESTDIR)/etc/iwan
	@if [ ! -f $(DESTDIR)/etc/iwan/iwan.conf ]; then \
		install -m 0600 openwrt/iwan.conf.example $(DESTDIR)/etc/iwan/iwan.conf; \
	fi
	install -d $(DESTDIR)/etc/init.d
	install -m 0755 openwrt/iwand.init $(DESTDIR)/etc/init.d/iwand

install-freebsd: $(TARGET)
	install -d $(DESTDIR)$(PREFIX)/sbin
	install -m 0755 $(TARGET) $(DESTDIR)$(PREFIX)/sbin/
	install -d $(DESTDIR)$(PREFIX)/etc/iwan
	@if [ ! -f $(DESTDIR)$(PREFIX)/etc/iwan/iwan.conf ]; then \
		install -m 0600 openwrt/iwan.conf.example $(DESTDIR)$(PREFIX)/etc/iwan/iwan.conf; \
	fi
	install -d $(DESTDIR)$(PREFIX)/etc/rc.d
	install -m 0755 freebsd/iwand.rc $(DESTDIR)$(PREFIX)/etc/rc.d/iwand

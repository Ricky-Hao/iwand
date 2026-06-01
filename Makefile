CC       ?= gcc
STRIP    ?= strip
CFLAGS   ?= -O2 -Wall -Wextra -Wno-unused-parameter
LDFLAGS  ?=
TARGET   = iwand
SRC      = src/iwand.c

.PHONY: all static clean install

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

static: $(SRC)
	$(CC) $(CFLAGS) -static -o $(TARGET) $^ $(LDFLAGS)
	@which $(STRIP) >/dev/null 2>&1 && $(STRIP) $(TARGET) || strip $(TARGET) 2>/dev/null || true

clean:
	rm -f $(TARGET)

install: $(TARGET)
	install -d $(DESTDIR)/usr/sbin
	install -m 0755 $(TARGET) $(DESTDIR)/usr/sbin/
	install -d $(DESTDIR)/etc/sdwan
	@if [ ! -f $(DESTDIR)/etc/sdwan/iwan.conf ]; then \
		install -m 0600 openwrt/iwan.conf.example $(DESTDIR)/etc/sdwan/iwan.conf; \
	fi
	install -d $(DESTDIR)/etc/init.d
	install -m 0755 openwrt/iwand.init $(DESTDIR)/etc/init.d/iwand

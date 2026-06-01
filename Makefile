CC       ?= gcc
CFLAGS   ?= -O2 -Wall -Wextra -Wno-unused-parameter
LDFLAGS  ?=
TARGET   = iwand
SRC      = src/iwand.c

.PHONY: all static clean install

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

static: $(SRC)
	$(CC) $(CFLAGS) -static -fno-link-libatomic -o $(TARGET) $^ $(LDFLAGS)
	@which strip >/dev/null 2>&1 && strip $(TARGET) || true

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

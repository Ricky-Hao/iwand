#ifndef IWAND_TUN_H
#define IWAND_TUN_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>

typedef void (*tun_log_fn)(const char *fmt, ...);

int tun_open(char *dev, size_t dev_len, tun_log_fn log_fn);
int tun_set_ip(const char *dev, uint32_t ip, uint32_t mask, tun_log_fn log_fn);
int tun_set_mtu(const char *dev, int mtu, tun_log_fn log_fn);
void tun_clear_ip(const char *dev, tun_log_fn log_fn);

#endif /* IWAND_TUN_H */

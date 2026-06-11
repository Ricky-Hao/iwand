#if defined(__linux__)
#define _GNU_SOURCE

#include "tun.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>

#ifdef __has_include
#  if __has_include(<linux/if_tun.h>)
#    include <linux/if_tun.h>
#  endif
#endif
#ifndef TUNSETIFF
#  define TUNSETIFF     _IOW('T', 202, int)
#  define IFF_TUN       0x0001
#  define IFF_NO_PI     0x1000
#endif

int tun_open(char *dev, size_t dev_len, tun_log_fn log_fn)
{
    (void)dev_len;

    int fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        if (log_fn)
            log_fn("open /dev/net/tun failed: %s\n", strerror(errno));
        return -1;
    }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", dev);
    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        if (log_fn)
            log_fn("TUNSETIFF failed: %s\n", strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

int tun_set_ip(const char *dev, uint32_t ip, uint32_t mask, tun_log_fn log_fn)
{
    int sockfd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (sockfd < 0) return -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", dev);

    struct sockaddr_in *addr = (struct sockaddr_in *)&ifr.ifr_addr;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = ip;
    if (ioctl(sockfd, SIOCSIFADDR, &ifr) < 0) {
        if (log_fn)
            log_fn("SIOCSIFADDR failed: %s\n", strerror(errno));
        close(sockfd);
        return -1;
    }

    addr->sin_addr.s_addr = mask;
    if (ioctl(sockfd, SIOCSIFNETMASK, &ifr) < 0) {
        if (log_fn)
            log_fn("SIOCSIFNETMASK failed: %s\n", strerror(errno));
        close(sockfd);
        return -1;
    }

    if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) {
        if (log_fn)
            log_fn("SIOCGIFFLAGS failed: %s\n", strerror(errno));
        close(sockfd);
        return -1;
    }
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0) {
        if (log_fn)
            log_fn("SIOCSIFFLAGS UP failed: %s\n", strerror(errno));
        close(sockfd);
        return -1;
    }

    close(sockfd);
    return 0;
}

int tun_set_mtu(const char *dev, int mtu, tun_log_fn log_fn)
{
    int sockfd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (sockfd < 0) return -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", dev);
    ifr.ifr_mtu = mtu;
    int ret = ioctl(sockfd, SIOCSIFMTU, &ifr);
    if (ret < 0 && log_fn)
        log_fn("SIOCSIFMTU(%d) failed: %s\n", mtu, strerror(errno));
    close(sockfd);
    return ret;
}

void tun_clear_ip(const char *dev, tun_log_fn log_fn)
{
    (void)log_fn;

    int sockfd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (sockfd < 0) return;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", dev);

    struct sockaddr_in *addr = (struct sockaddr_in *)&ifr.ifr_addr;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = 0;
    ioctl(sockfd, SIOCSIFADDR, &ifr);

    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", dev);
    ioctl(sockfd, SIOCGIFFLAGS, &ifr);
    ifr.ifr_flags &= ~(IFF_UP | IFF_RUNNING);
    ioctl(sockfd, SIOCSIFFLAGS, &ifr);
    close(sockfd);
}

#elif !defined(__FreeBSD__)

#include "tun.h"

int tun_open(char *dev, size_t dev_len, tun_log_fn log_fn)
{
    (void)dev;
    (void)dev_len;
    if (log_fn)
        log_fn("TUN is unsupported on this platform\n");
    return -1;
}

int tun_set_ip(const char *dev, uint32_t ip, uint32_t mask, tun_log_fn log_fn)
{
    (void)dev;
    (void)ip;
    (void)mask;
    (void)log_fn;
    return -1;
}

int tun_set_mtu(const char *dev, int mtu, tun_log_fn log_fn)
{
    (void)dev;
    (void)mtu;
    (void)log_fn;
    return -1;
}

void tun_clear_ip(const char *dev, tun_log_fn log_fn)
{
    (void)dev;
    (void)log_fn;
}

#else
typedef int tun_linux_empty_translation_unit;
#endif

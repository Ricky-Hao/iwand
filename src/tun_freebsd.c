#if defined(__FreeBSD__)

#include "tun.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <net/if_tun.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static void freebsd_sockaddr_in(struct sockaddr_in *addr, uint32_t ip)
{
    memset(addr, 0, sizeof(*addr));
    addr->sin_len = sizeof(*addr);
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = ip;
}

static int freebsd_is_tun_unit(const char *dev)
{
    const char *p;

    if (strncmp(dev, "tun", 3) != 0)
        return 0;
    p = dev + 3;
    if (*p == '\0')
        return 0;
    while (*p) {
        if (*p < '0' || *p > '9')
            return 0;
        p++;
    }
    return 1;
}

static int freebsd_open_tun_device(const char *dev, int *cloned, tun_log_fn log_fn)
{
    int fd;

    *cloned = 0;
    fd = open("/dev/tun", O_RDWR | O_CLOEXEC);
    if (fd >= 0) {
        *cloned = 1;
        return fd;
    }

    if (freebsd_is_tun_unit(dev)) {
        char path[sizeof("/dev/") + IFNAMSIZ];

        snprintf(path, sizeof(path), "/dev/%s", dev);
        fd = open(path, O_RDWR | O_CLOEXEC);
        if (fd >= 0)
            return fd;
        if (log_fn)
            log_fn("open %s failed: %s\n", path, strerror(errno));
    } else {
        if (log_fn)
            log_fn("open /dev/tun failed: %s\n", strerror(errno));
    }

    return -1;
}

static int freebsd_get_tun_name(int fd, char *name, size_t name_len, tun_log_fn log_fn)
{
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    if (ioctl(fd, TUNGIFNAME, &ifr) < 0) {
        if (log_fn)
            log_fn("TUNGIFNAME failed: %s\n", strerror(errno));
        return -1;
    }
    snprintf(name, name_len, "%.*s", IFNAMSIZ - 1, ifr.ifr_name);
    return 0;
}

static int freebsd_rename_tun(const char *old_name, const char *new_name, int *saved_errno)
{
    int sockfd;
    struct ifreq ifr;
    char new_name_buf[IFNAMSIZ];
    int ret;

    if (strcmp(old_name, new_name) == 0)
        return 0;

    sockfd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (sockfd < 0) {
        *saved_errno = errno;
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", old_name);
    snprintf(new_name_buf, sizeof(new_name_buf), "%s", new_name);
    ifr.ifr_data = (caddr_t)new_name_buf;

    ret = ioctl(sockfd, SIOCSIFNAME, &ifr);
    if (ret < 0)
        *saved_errno = errno;
    close(sockfd);
    return ret;
}

int tun_open(char *dev, size_t dev_len, tun_log_fn log_fn)
{
    int cloned;
    int fd = freebsd_open_tun_device(dev, &cloned, log_fn);
    if (fd < 0)
        return -1;

    int off = 0;
    if (ioctl(fd, TUNSLMODE, &off) < 0) {
        if (log_fn)
            log_fn("TUNSLMODE off failed: %s\n", strerror(errno));
        close(fd);
        return -1;
    }
    if (ioctl(fd, TUNSIFHEAD, &off) < 0) {
        if (log_fn)
            log_fn("TUNSIFHEAD off failed: %s\n", strerror(errno));
        close(fd);
        return -1;
    }

    int mode = IFF_BROADCAST | IFF_MULTICAST;
    if (ioctl(fd, TUNSIFMODE, &mode) < 0) {
        if (log_fn)
            log_fn("TUNSIFMODE failed: %s\n", strerror(errno));
        close(fd);
        return -1;
    }

#ifdef TUNSTRANSIENT
    if (cloned) {
        int transient = 1;
        if (ioctl(fd, TUNSTRANSIENT, &transient) < 0 && log_fn)
            log_fn("TUNSTRANSIENT warning: %s\n", strerror(errno));
    }
#endif

    char actual[IFNAMSIZ];
    if (freebsd_get_tun_name(fd, actual, sizeof(actual), log_fn) < 0) {
        close(fd);
        return -1;
    }

    if (strcmp(actual, dev) != 0) {
        int rename_errno = 0;
        if (freebsd_rename_tun(actual, dev, &rename_errno) == 0) {
            if (log_fn)
                log_fn("renamed FreeBSD TUN %s -> %s\n", actual, dev);
        } else {
            if (log_fn) {
                log_fn("rename FreeBSD TUN %s -> %s failed: %s; using %s\n",
                       actual, dev, strerror(rename_errno), actual);
            }
            snprintf(dev, dev_len, "%s", actual);
        }
    }

    return fd;
}

int tun_set_ip(const char *dev, uint32_t ip, uint32_t mask, tun_log_fn log_fn)
{
    int sockfd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (sockfd < 0) return -1;

    struct ifaliasreq ifra;
    memset(&ifra, 0, sizeof(ifra));
    snprintf(ifra.ifra_name, sizeof(ifra.ifra_name), "%s", dev);

    freebsd_sockaddr_in((struct sockaddr_in *)&ifra.ifra_addr, ip);
    freebsd_sockaddr_in((struct sockaddr_in *)&ifra.ifra_mask, mask);

    uint32_t ip_h = ntohl(ip);
    uint32_t mask_h = ntohl(mask);
    uint32_t broad = htonl((ip_h & mask_h) | ~mask_h);
    freebsd_sockaddr_in((struct sockaddr_in *)&ifra.ifra_broadaddr, broad);

    int ret = ioctl(sockfd, SIOCAIFADDR, &ifra);
    int add_errno = errno;
    if (ret < 0 && add_errno == EEXIST) {
        struct ifreq del;

        memset(&del, 0, sizeof(del));
        snprintf(del.ifr_name, IFNAMSIZ, "%s", dev);
        freebsd_sockaddr_in((struct sockaddr_in *)&del.ifr_addr, ip);
        if (ioctl(sockfd, SIOCDIFADDR, &del) == 0) {
            ret = ioctl(sockfd, SIOCAIFADDR, &ifra);
            add_errno = errno;
        }
    }
    if (ret < 0) {
        if (log_fn)
            log_fn("SIOCAIFADDR failed: %s\n", strerror(add_errno));
        close(sockfd);
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", dev);
    if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) {
        if (log_fn)
            log_fn("SIOCGIFFLAGS failed: %s\n", strerror(errno));
        close(sockfd);
        return -1;
    }
    ifr.ifr_flags |= IFF_UP;
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
    if (ioctl(sockfd, SIOCGIFADDR, &ifr) == 0)
        ioctl(sockfd, SIOCDIFADDR, &ifr);

    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", dev);
    if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) == 0) {
        ifr.ifr_flags &= ~IFF_UP;
        ioctl(sockfd, SIOCSIFFLAGS, &ifr);
    }
    close(sockfd);
}

#else
typedef int tun_freebsd_empty_translation_unit;
#endif

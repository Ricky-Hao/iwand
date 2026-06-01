/*
 * iwand - Panabit iWAN SD-WAN Client (OpenWrt-compatible reimplementation)
 *
 * Reverse-engineered from binary analysis of the original linux_sdwand_x86.
 * Compatible with musl libc (OpenWrt) and glibc.
 *
 * Protocol: UDP-based tunnel with TUN interface, AES/XOR encryption,
 *           MD5-based packet signing, TLV-encoded control messages.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#ifdef __has_include
#  if __has_include(<linux/if_tun.h>)
#    include <linux/if_tun.h>
#  endif
#endif
#ifndef TUNSETIFF
#  include <sys/ioctl.h>
#  define TUNSETIFF     _IOW('T', 202, int)
#  define IFF_TUN       0x0001
#  define IFF_NO_PI     0x1000
#endif
#include <netdb.h>
#include <stdarg.h>

/* ── Packet types ───────────────────────────────────────── */
#define PKT_OPENREJ   0x11
#define PKT_OPENACK   0x12
#define PKT_OPEN      0x13
#define PKT_DATA      0x14
#define PKT_ECHOREQ   0x15
#define PKT_ECHORESP  0x16
#define PKT_CLOSE     0x17
#define PKT_DATA_ENC  0x18
#define PKT_IPFRAG    0x21
#define PKT_SEGRT     0x27

/* ── Client states ──────────────────────────────────────── */
#define STATE_NOT_READY  0
#define STATE_DNS_NEEDED 2
#define STATE_IP_READY   3
#define STATE_AUTH_SENT  4
#define STATE_ESTABLISHED 5
#define STATE_CLOSED     6

/* ── Timeouts (seconds) ─────────────────────────────────── */
#define AUTH_TIMEOUT     6
#define AUTH_RETRY_INTERVAL 2
#define DATA_TIMEOUT     15
#define ECHO_INTERVAL    2  /* every 2 timer ticks */

/* ── Buffer sizes ───────────────────────────────────────── */
#define MAX_PKT_SIZE   2048
#define HDR_SIZE       8
#define SIGN_SIZE      16
#define TUN_BUF_OFFSET 8  /* leave room for header before TUN data */

/* ── IP fragment reassembly ─────────────────────────────── */
#define FRAG_SLOTS     10
#define FRAG_BUF_SIZE  2048
#define FRAG_TIMEOUT   5   /* seconds */
#define ETHPKT_SIZE    16  /* sdwan_ethpkt header size */

/* ── Forward declarations ───────────────────────────────── */
static void log_msg(const char *fmt, ...);

/* ──────────────────────────────────────────────────────────
 *  MD5 implementation (matches the original binary's sys_md5)
 * ────────────────────────────────────────────────────────── */

typedef struct {
    uint32_t state[4];
    uint64_t count;
    uint8_t  buffer[64];
} md5_ctx_t;

#define MD5_F(x,y,z) (((x)&(y))|((~(x))&(z)))
#define MD5_G(x,y,z) (((x)&(z))|((y)&(~(z))))
#define MD5_H(x,y,z) ((x)^(y)^(z))
#define MD5_I(x,y,z) ((y)^((x)|(~(z))))
#define MD5_ROT(x,n) (((x)<<(n))|((x)>>(32-(n))))

#define MD5_FF(a,b,c,d,x,s,ac) { (a)+=MD5_F((b),(c),(d))+(x)+(uint32_t)(ac); (a)=MD5_ROT((a),(s)); (a)+=(b); }
#define MD5_GG(a,b,c,d,x,s,ac) { (a)+=MD5_G((b),(c),(d))+(x)+(uint32_t)(ac); (a)=MD5_ROT((a),(s)); (a)+=(b); }
#define MD5_HH(a,b,c,d,x,s,ac) { (a)+=MD5_H((b),(c),(d))+(x)+(uint32_t)(ac); (a)=MD5_ROT((a),(s)); (a)+=(b); }
#define MD5_II(a,b,c,d,x,s,ac) { (a)+=MD5_I((b),(c),(d))+(x)+(uint32_t)(ac); (a)=MD5_ROT((a),(s)); (a)+=(b); }

static void md5_transform(uint32_t state[4], const uint8_t block[64])
{
    uint32_t a=state[0], b=state[1], c=state[2], d=state[3];
    uint32_t x[16];
    for (int i = 0; i < 16; i++)
        x[i] = (uint32_t)block[i*4] | ((uint32_t)block[i*4+1]<<8) |
                ((uint32_t)block[i*4+2]<<16) | ((uint32_t)block[i*4+3]<<24);

    MD5_FF(a,b,c,d,x[ 0], 7,0xd76aa478); MD5_FF(d,a,b,c,x[ 1],12,0xe8c7b756);
    MD5_FF(c,d,a,b,x[ 2],17,0x242070db); MD5_FF(b,c,d,a,x[ 3],22,0xc1bdceee);
    MD5_FF(a,b,c,d,x[ 4], 7,0xf57c0faf); MD5_FF(d,a,b,c,x[ 5],12,0x4787c62a);
    MD5_FF(c,d,a,b,x[ 6],17,0xa8304613); MD5_FF(b,c,d,a,x[ 7],22,0xfd469501);
    MD5_FF(a,b,c,d,x[ 8], 7,0x698098d8); MD5_FF(d,a,b,c,x[ 9],12,0x8b44f7af);
    MD5_FF(c,d,a,b,x[10],17,0xffff5bb1); MD5_FF(b,c,d,a,x[11],22,0x895cd7be);
    MD5_FF(a,b,c,d,x[12], 7,0x6b901122); MD5_FF(d,a,b,c,x[13],12,0xfd987193);
    MD5_FF(c,d,a,b,x[14],17,0xa679438e); MD5_FF(b,c,d,a,x[15],22,0x49b40821);

    MD5_GG(a,b,c,d,x[ 1], 5,0xf61e2562); MD5_GG(d,a,b,c,x[ 6], 9,0xc040b340);
    MD5_GG(c,d,a,b,x[11],14,0x265e5a51); MD5_GG(b,c,d,a,x[ 0],20,0xe9b6c7aa);
    MD5_GG(a,b,c,d,x[ 5], 5,0xd62f105d); MD5_GG(d,a,b,c,x[10], 9,0x02441453);
    MD5_GG(c,d,a,b,x[15],14,0xd8a1e681); MD5_GG(b,c,d,a,x[ 4],20,0xe7d3fbc8);
    MD5_GG(a,b,c,d,x[ 9], 5,0x21e1cde6); MD5_GG(d,a,b,c,x[14], 9,0xc33707d6);
    MD5_GG(c,d,a,b,x[ 3],14,0xf4d50d87); MD5_GG(b,c,d,a,x[ 8],20,0x455a14ed);
    MD5_GG(a,b,c,d,x[13], 5,0xa9e3e905); MD5_GG(d,a,b,c,x[ 2], 9,0xfcefa3f8);
    MD5_GG(c,d,a,b,x[ 7],14,0x676f02d9); MD5_GG(b,c,d,a,x[12],20,0x8d2a4c8a);

    MD5_HH(a,b,c,d,x[ 5], 4,0xfffa3942); MD5_HH(d,a,b,c,x[ 8],11,0x8771f681);
    MD5_HH(c,d,a,b,x[11],16,0x6d9d6122); MD5_HH(b,c,d,a,x[14],23,0xfde5380c);
    MD5_HH(a,b,c,d,x[ 1], 4,0xa4beea44); MD5_HH(d,a,b,c,x[ 4],11,0x4bdecfa9);
    MD5_HH(c,d,a,b,x[ 7],16,0xf6bb4b60); MD5_HH(b,c,d,a,x[10],23,0xbebfbc70);
    MD5_HH(a,b,c,d,x[13], 4,0x289b7ec6); MD5_HH(d,a,b,c,x[ 0],11,0xeaa127fa);
    MD5_HH(c,d,a,b,x[ 3],16,0xd4ef3085); MD5_HH(b,c,d,a,x[ 6],23,0x04881d05);
    MD5_HH(a,b,c,d,x[ 9], 4,0xd9d4d039); MD5_HH(d,a,b,c,x[12],11,0xe6db99e5);
    MD5_HH(c,d,a,b,x[15],16,0x1fa27cf8); MD5_HH(b,c,d,a,x[ 2],23,0xc4ac5665);

    MD5_II(a,b,c,d,x[ 0], 6,0xf4292244); MD5_II(d,a,b,c,x[ 7],10,0x432aff97);
    MD5_II(c,d,a,b,x[14],15,0xab9423a7); MD5_II(b,c,d,a,x[ 5],21,0xfc93a039);
    MD5_II(a,b,c,d,x[12], 6,0x655b59c3); MD5_II(d,a,b,c,x[ 3],10,0x8f0ccc92);
    MD5_II(c,d,a,b,x[10],15,0xffeff47d); MD5_II(b,c,d,a,x[ 1],21,0x85845dd1);
    MD5_II(a,b,c,d,x[ 8], 6,0x6fa87e4f); MD5_II(d,a,b,c,x[15],10,0xfe2ce6e0);
    MD5_II(c,d,a,b,x[ 6],15,0xa3014314); MD5_II(b,c,d,a,x[13],21,0x4e0811a1);
    MD5_II(a,b,c,d,x[ 4], 6,0xf7537e82); MD5_II(d,a,b,c,x[11],10,0xbd3af235);
    MD5_II(c,d,a,b,x[ 2],15,0x2ad7d2bb); MD5_II(b,c,d,a,x[ 9],21,0xeb86d391);

    state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d;
}

static void md5_init(md5_ctx_t *ctx)
{
    ctx->count = 0;
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xefcdab89;
    ctx->state[2] = 0x98badcfe;
    ctx->state[3] = 0x10325476;
}

static void md5_update(md5_ctx_t *ctx, const uint8_t *input, uint32_t len)
{
    uint32_t idx = (uint32_t)(ctx->count & 0x3f);
    ctx->count += len;
    uint32_t part_len = 64 - idx;
    uint32_t i = 0;
    if (len >= part_len) {
        memcpy(ctx->buffer + idx, input, part_len);
        md5_transform(ctx->state, ctx->buffer);
        for (i = part_len; i + 63 < len; i += 64)
            md5_transform(ctx->state, input + i);
        idx = 0;
    }
    memcpy(ctx->buffer + idx, input + i, len - i);
}

static void md5_final(uint8_t digest[16], md5_ctx_t *ctx)
{
    static const uint8_t padding[64] = { 0x80 };
    uint8_t bits[8];
    uint64_t bit_count = ctx->count << 3;
    for (int i = 0; i < 8; i++)
        bits[i] = (uint8_t)(bit_count >> (i * 8));
    uint32_t idx = (uint32_t)(ctx->count & 0x3f);
    uint32_t pad_len = (idx < 56) ? (56 - idx) : (120 - idx);
    md5_update(ctx, padding, pad_len);
    md5_update(ctx, bits, 8);
    for (int i = 0; i < 4; i++) {
        digest[i*4  ] = (uint8_t)(ctx->state[i]);
        digest[i*4+1] = (uint8_t)(ctx->state[i] >> 8);
        digest[i*4+2] = (uint8_t)(ctx->state[i] >> 16);
        digest[i*4+3] = (uint8_t)(ctx->state[i] >> 24);
    }
}

static void md5_hash(const void *data, uint32_t len, uint8_t digest[16])
{
    md5_ctx_t ctx;
    md5_init(&ctx);
    md5_update(&ctx, data, len);
    md5_final(digest, &ctx);
}

/* ──────────────────────────────────────────────────────────
 *  AES-128-ECB (minimal, only used for password encryption)
 * ────────────────────────────────────────────────────────── */

static const uint8_t aes_sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint32_t aes_rcon[10] = {
    0x01000000,0x02000000,0x04000000,0x08000000,0x10000000,
    0x20000000,0x40000000,0x80000000,0x1b000000,0x36000000
};

typedef struct {
    uint32_t rd_key[44]; /* 4 * (10+1) round keys for AES-128 */
} aes_key_t;

static uint32_t aes_sub_word(uint32_t w)
{
    return ((uint32_t)aes_sbox[(w>>24)&0xff] << 24) |
           ((uint32_t)aes_sbox[(w>>16)&0xff] << 16) |
           ((uint32_t)aes_sbox[(w>> 8)&0xff] <<  8) |
           ((uint32_t)aes_sbox[(w    )&0xff]);
}

static void aes_set_encrypt_key(const uint8_t key[16], aes_key_t *aeskey)
{
    uint32_t *rk = aeskey->rd_key;
    for (int i = 0; i < 4; i++)
        rk[i] = ((uint32_t)key[4*i]<<24) | ((uint32_t)key[4*i+1]<<16) |
                 ((uint32_t)key[4*i+2]<<8) | (uint32_t)key[4*i+3];
    for (int i = 4; i < 44; i++) {
        uint32_t t = rk[i-1];
        if ((i & 3) == 0)
            t = aes_sub_word((t<<8)|(t>>24)) ^ aes_rcon[(i>>2)-1];
        rk[i] = rk[i-4] ^ t;
    }
}

static void aes_encrypt_block(const uint8_t in[16], uint8_t out[16], const aes_key_t *aeskey)
{
    /* AES-128 tables-based encryption */
    static const uint8_t xtime_table[256] = {
        0x00,0x02,0x04,0x06,0x08,0x0a,0x0c,0x0e,0x10,0x12,0x14,0x16,0x18,0x1a,0x1c,0x1e,
        0x20,0x22,0x24,0x26,0x28,0x2a,0x2c,0x2e,0x30,0x32,0x34,0x36,0x38,0x3a,0x3c,0x3e,
        0x40,0x42,0x44,0x46,0x48,0x4a,0x4c,0x4e,0x50,0x52,0x54,0x56,0x58,0x5a,0x5c,0x5e,
        0x60,0x62,0x64,0x66,0x68,0x6a,0x6c,0x6e,0x70,0x72,0x74,0x76,0x78,0x7a,0x7c,0x7e,
        0x80,0x82,0x84,0x86,0x88,0x8a,0x8c,0x8e,0x90,0x92,0x94,0x96,0x98,0x9a,0x9c,0x9e,
        0xa0,0xa2,0xa4,0xa6,0xa8,0xaa,0xac,0xae,0xb0,0xb2,0xb4,0xb6,0xb8,0xba,0xbc,0xbe,
        0xc0,0xc2,0xc4,0xc6,0xc8,0xca,0xcc,0xce,0xd0,0xd2,0xd4,0xd6,0xd8,0xda,0xdc,0xde,
        0xe0,0xe2,0xe4,0xe6,0xe8,0xea,0xec,0xee,0xf0,0xf2,0xf4,0xf6,0xf8,0xfa,0xfc,0xfe,
        0x1b,0x19,0x1f,0x1d,0x13,0x11,0x17,0x15,0x0b,0x09,0x0f,0x0d,0x03,0x01,0x07,0x05,
        0x3b,0x39,0x3f,0x3d,0x33,0x31,0x37,0x35,0x2b,0x29,0x2f,0x2d,0x23,0x21,0x27,0x25,
        0x5b,0x59,0x5f,0x5d,0x53,0x51,0x57,0x55,0x4b,0x49,0x4f,0x4d,0x43,0x41,0x47,0x45,
        0x7b,0x79,0x7f,0x7d,0x73,0x71,0x77,0x75,0x6b,0x69,0x6f,0x6d,0x63,0x61,0x67,0x65,
        0x9b,0x99,0x9f,0x9d,0x93,0x91,0x97,0x95,0x8b,0x89,0x8f,0x8d,0x83,0x81,0x87,0x85,
        0xbb,0xb9,0xbf,0xbd,0xb3,0xb1,0xb7,0xb5,0xab,0xa9,0xaf,0xad,0xa3,0xa1,0xa7,0xa5,
        0xdb,0xd9,0xdf,0xdd,0xd3,0xd1,0xd7,0xd5,0xcb,0xc9,0xcf,0xcd,0xc3,0xc1,0xc7,0xc5,
        0xfb,0xf9,0xff,0xfd,0xf3,0xf1,0xf7,0xf5,0xeb,0xe9,0xef,0xed,0xe3,0xe1,0xe7,0xe5
    };
    #define XT(x) xtime_table[(x)]

    uint8_t s[16];
    const uint32_t *rk = aeskey->rd_key;

    /* AddRoundKey (round 0) */
    for (int i = 0; i < 16; i++)
        s[i] = in[i] ^ ((rk[i>>2] >> (24 - 8*(i&3))) & 0xff);

    /* Rounds 1-9 */
    for (int round = 1; round <= 9; round++) {
        uint8_t t[16];
        /* SubBytes */
        for (int i = 0; i < 16; i++)
            t[i] = aes_sbox[s[i]];
        /* ShiftRows */
        s[ 0]=t[ 0]; s[ 1]=t[ 5]; s[ 2]=t[10]; s[ 3]=t[15];
        s[ 4]=t[ 4]; s[ 5]=t[ 9]; s[ 6]=t[14]; s[ 7]=t[ 3];
        s[ 8]=t[ 8]; s[ 9]=t[13]; s[10]=t[ 2]; s[11]=t[ 7];
        s[12]=t[12]; s[13]=t[ 1]; s[14]=t[ 6]; s[15]=t[11];
        /* MixColumns */
        for (int c = 0; c < 4; c++) {
            int i = c * 4;
            uint8_t a0=s[i], a1=s[i+1], a2=s[i+2], a3=s[i+3];
            s[i  ] = XT(a0)^XT(a1)^a1^a2^a3;
            s[i+1] = a0^XT(a1)^XT(a2)^a2^a3;
            s[i+2] = a0^a1^XT(a2)^XT(a3)^a3;
            s[i+3] = XT(a0)^a0^a1^a2^XT(a3);
        }
        /* AddRoundKey */
        for (int i = 0; i < 16; i++)
            s[i] ^= (rk[round*4 + (i>>2)] >> (24 - 8*(i&3))) & 0xff;
    }

    /* Final round (no MixColumns) */
    {
        uint8_t t[16];
        for (int i = 0; i < 16; i++)
            t[i] = aes_sbox[s[i]];
        s[ 0]=t[ 0]; s[ 1]=t[ 5]; s[ 2]=t[10]; s[ 3]=t[15];
        s[ 4]=t[ 4]; s[ 5]=t[ 9]; s[ 6]=t[14]; s[ 7]=t[ 3];
        s[ 8]=t[ 8]; s[ 9]=t[13]; s[10]=t[ 2]; s[11]=t[ 7];
        s[12]=t[12]; s[13]=t[ 1]; s[14]=t[ 6]; s[15]=t[11];
        for (int i = 0; i < 16; i++)
            s[i] ^= (rk[40 + (i>>2)] >> (24 - 8*(i&3))) & 0xff;
    }

    memcpy(out, s, 16);
    #undef XT
}

/* AES-128 decryption (for segment routing) */
static const uint8_t aes_inv_sbox[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

static void aes_set_decrypt_key(const uint8_t key[16], aes_key_t *aeskey)
{
    /* Generate encrypt schedule first, then reverse round key order.
     * aes_decrypt_block() uses the direct inverse cipher
     * (InvShiftRows→InvSubBytes→AddRoundKey→InvMixColumns),
     * which requires plain-swapped round keys without further transform. */
    aes_set_encrypt_key(key, aeskey);
    uint32_t *rk = aeskey->rd_key;
    /* Swap round keys: round 0 <-> round 10, 1 <-> 9, 2 <-> 8, 3 <-> 7, 4 <-> 6 */
    for (int i = 0; i < 5; i++) {
        for (int j = 0; j < 4; j++) {
            uint32_t t = rk[i*4+j];
            rk[i*4+j] = rk[(10-i)*4+j];
            rk[(10-i)*4+j] = t;
        }
    }
}

static void aes_decrypt_block(const uint8_t in[16], uint8_t out[16], const aes_key_t *aeskey)
{
    uint8_t s[16];
    const uint32_t *rk = aeskey->rd_key;

    /* AddRoundKey (round 0, which is the last encrypt round key) */
    for (int i = 0; i < 16; i++)
        s[i] = in[i] ^ ((rk[i>>2] >> (24 - 8*(i&3))) & 0xff);

    /* Rounds 1-9: InvShiftRows, InvSubBytes, AddRoundKey, InvMixColumns */
    for (int round = 1; round <= 9; round++) {
        uint8_t t[16];
        /* InvShiftRows */
        t[ 0]=s[ 0]; t[ 1]=s[13]; t[ 2]=s[10]; t[ 3]=s[ 7];
        t[ 4]=s[ 4]; t[ 5]=s[ 1]; t[ 6]=s[14]; t[ 7]=s[11];
        t[ 8]=s[ 8]; t[ 9]=s[ 5]; t[10]=s[ 2]; t[11]=s[15];
        t[12]=s[12]; t[13]=s[ 9]; t[14]=s[ 6]; t[15]=s[ 3];
        /* InvSubBytes */
        for (int i = 0; i < 16; i++)
            s[i] = aes_inv_sbox[t[i]];
        /* AddRoundKey */
        for (int i = 0; i < 16; i++)
            s[i] ^= (rk[round*4 + (i>>2)] >> (24 - 8*(i&3))) & 0xff;
        /* InvMixColumns */
        #define xtime(x) (((x)<<1) ^ ((((x)>>7)&1)*0x1b))
        #define mul9(x) (xtime(xtime(xtime(x)))^(x))
        #define mul11(x) (xtime(xtime(xtime(x))^(x))^(x))
        #define mul13(x) (xtime(xtime(xtime(x)^(x)))^(x))
        #define mul14(x) (xtime(xtime(xtime(x)^(x))^(x)))
        for (int c = 0; c < 4; c++) {
            int i = c * 4;
            uint8_t a0=s[i],a1=s[i+1],a2=s[i+2],a3=s[i+3];
            s[i  ] = mul14(a0)^mul11(a1)^mul13(a2)^mul9(a3);
            s[i+1] = mul9(a0)^mul14(a1)^mul11(a2)^mul13(a3);
            s[i+2] = mul13(a0)^mul9(a1)^mul14(a2)^mul11(a3);
            s[i+3] = mul11(a0)^mul13(a1)^mul9(a2)^mul14(a3);
        }
        #undef xtime
        #undef mul9
        #undef mul11
        #undef mul13
        #undef mul14
    }
    /* Final round: InvShiftRows, InvSubBytes, AddRoundKey */
    {
        uint8_t t[16];
        t[ 0]=s[ 0]; t[ 1]=s[13]; t[ 2]=s[10]; t[ 3]=s[ 7];
        t[ 4]=s[ 4]; t[ 5]=s[ 1]; t[ 6]=s[14]; t[ 7]=s[11];
        t[ 8]=s[ 8]; t[ 9]=s[ 5]; t[10]=s[ 2]; t[11]=s[15];
        t[12]=s[12]; t[13]=s[ 9]; t[14]=s[ 6]; t[15]=s[ 3];
        for (int i = 0; i < 16; i++)
            s[i] = aes_inv_sbox[t[i]];
        for (int i = 0; i < 16; i++)
            s[i] ^= (rk[40 + (i>>2)] >> (24 - 8*(i&3))) & 0xff;
    }
    memcpy(out, s, 16);
}

/* ──────────────────────────────────────────────────────────
 *  XOR encryption (data packets)
 * ────────────────────────────────────────────────────────── */

static void xor_encrypt(const uint8_t key[8], uint8_t *data, int len)
{
    for (int i = 0; i < len; i++)
        data[i] ^= key[i & 7];
}

/* ──────────────────────────────────────────────────────────
 *  Configuration
 * ────────────────────────────────────────────────────────── */

typedef struct {
    char server[64];
    char username[32];
    char password[32];
    char tun_name[IFNAMSIZ]; /* matches IFNAMSIZ to avoid truncation warnings */
    uint16_t port;
    uint16_t mtu;
    uint8_t  encrypt;
    uint16_t pipeid;
    uint16_t pipeidx;
    /* segment routing */
    uint8_t  sr_count;          /* number of SR links (0 = disabled) */
    uint32_t sr_links[6];       /* SR link IPs (network order) */
    uint8_t  sr_encrypt_mode;   /* 1=AES-128, 2=AES-256 */
    char     sr_password[32];
    /* paths for hook scripts */
    char up_script[256];
    char down_script[256];
} config_t;

static config_t g_cfg;

static int cfg_load(const char *path)
{
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        int len = strlen(line);
        /* Skip overlong lines: if no newline and not EOF, discard remainder */
        if (len > 0 && line[len-1] != '\n' && !feof(fp)) {
            int ch;
            while ((ch = fgetc(fp)) != EOF && ch != '\n')
                ;
            continue;
        }
        if (len == 0 || line[0] == '#' || line[0] == '\r' || line[0] == '\n')
            continue;
        /* strip trailing CR/LF */
        while (len > 0 && (line[len-1] == '\r' || line[len-1] == '\n'))
            line[--len] = '\0';
        if (len < 2) continue;

        /* Section header: [tun_name] */
        char *lb = strchr(line, '[');
        if (lb) {
            char *rb = strrchr(line, ']');
            if (rb && rb > lb) {
                *rb = '\0';
                strncpy(g_cfg.tun_name, lb + 1, sizeof(g_cfg.tun_name) - 1);
            }
            continue;
        }

        /* key=value */
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key = line;
        char *val = eq + 1;

        if (strcmp(key, "server") == 0)
            strncpy(g_cfg.server, val, sizeof(g_cfg.server) - 1);
        else if (strcmp(key, "username") == 0)
            strncpy(g_cfg.username, val, sizeof(g_cfg.username) - 1);
        else if (strcmp(key, "password") == 0)
            strncpy(g_cfg.password, val, sizeof(g_cfg.password) - 1);
        else if (strcmp(key, "port") == 0) {
            unsigned long v = strtoul(val, NULL, 10);
            if (v > 0 && v <= 65535) g_cfg.port = (uint16_t)v;
        }
        else if (strcmp(key, "mtu") == 0) {
            unsigned long v = strtoul(val, NULL, 10);
            if (v >= 46 && v <= 1600) g_cfg.mtu = (uint16_t)v;
        }
        else if (strcmp(key, "encrypt") == 0)
            g_cfg.encrypt = (val[0] == '1') ? 1 : 0;
        else if (strcmp(key, "pipeid") == 0) {
            unsigned long v = strtoul(val, NULL, 10);
            if (v <= 32767) g_cfg.pipeid = (uint16_t)v;
            else log_msg("config warning: pipeid %lu exceeds wire limit 32767\n", v);
        }
        else if (strcmp(key, "pipeidx") == 0) {
            unsigned long v = strtoul(val, NULL, 10);
            if (v <= 1) g_cfg.pipeidx = (uint16_t)v;
            else log_msg("config warning: pipeidx %lu exceeds wire limit 1\n", v);
        }
        else if (strcmp(key, "srlinks") == 0) {
            /* Parse comma-separated IP list: "1.2.3.4,5.6.7.8" or numeric */
            g_cfg.sr_count = 0;
            char tmp[256];
            strncpy(tmp, val, sizeof(tmp) - 1);
            tmp[sizeof(tmp) - 1] = '\0';
            char *p = tmp;
            while (*p && g_cfg.sr_count < 6) {
                char *comma = strchr(p, ',');
                if (comma) *comma = '\0';
                struct in_addr addr;
                if (inet_pton(AF_INET, p, &addr) == 1) {
                    g_cfg.sr_links[g_cfg.sr_count] = addr.s_addr;
                } else {
                    /* Fallback: try as numeric (protocol compat) */
                    g_cfg.sr_links[g_cfg.sr_count] = htonl(strtoul(p, NULL, 10));
                }
                g_cfg.sr_count++;
                if (!comma) break;
                p = comma + 1;
            }
        }
        else if (strcmp(key, "srpassword") == 0)
            strncpy(g_cfg.sr_password, val, sizeof(g_cfg.sr_password) - 1);
        else if (strcmp(key, "srencryptmode") == 0) {
            unsigned long v = strtoul(val, NULL, 10);
            if (v <= 2) g_cfg.sr_encrypt_mode = (uint8_t)v;
        }
        else if (strcmp(key, "up_script") == 0)
            strncpy(g_cfg.up_script, val, sizeof(g_cfg.up_script) - 1);
        else if (strcmp(key, "down_script") == 0)
            strncpy(g_cfg.down_script, val, sizeof(g_cfg.down_script) - 1);
    }
    fclose(fp);
    return 0;
}

static int cfg_valid(void)
{
    if (g_cfg.tun_name[0] == '\0') {
        log_msg("config error: no TUN name (need [section] header)\n");
        return 0;
    }
    if (g_cfg.server[0] == '\0') {
        log_msg("config error: no server\n");
        return 0;
    }
    if (g_cfg.username[0] == '\0') {
        log_msg("config error: no username\n");
        return 0;
    }
    if (g_cfg.password[0] == '\0') {
        log_msg("config error: no password\n");
        return 0;
    }
    if (strlen(g_cfg.password) > 16) {
        log_msg("config warning: password longer than 16 chars will be truncated\n");
    }
    if (g_cfg.mtu < 46 || g_cfg.mtu > 1600) {
        log_msg("config error: MTU must be 46-1600 (got %d)\n", g_cfg.mtu);
        return 0;
    }
    if (g_cfg.port == 0) {
        log_msg("config error: no port\n");
        return 0;
    }
    return 1;
}

/* ──────────────────────────────────────────────────────────
 *  Logging
 * ────────────────────────────────────────────────────────── */

#include <syslog.h>

static FILE *g_logfp = NULL;
static int g_foreground = 0;
static int g_use_syslog = 0;

static void log_msg(const char *fmt, ...)
{
    va_list ap;

    if (g_use_syslog) {
        va_start(ap, fmt);
        vsyslog(LOG_INFO, fmt, ap);
        va_end(ap);
        return;
    }

    FILE *out = g_logfp ? g_logfp : stderr;

    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    fprintf(out, "%04d-%02d-%02d %02d:%02d:%02d ",
            tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday,
            tm->tm_hour, tm->tm_min, tm->tm_sec);

    va_start(ap, fmt);
    vfprintf(out, fmt, ap);
    va_end(ap);
    fflush(out);
}

static void log_init(const char *path)
{
    if (path && path[0]) {
        g_logfp = fopen(path, "ae"); /* "e" sets O_CLOEXEC */
        if (!g_logfp)
            fprintf(stderr, "warning: cannot open log file %s\n", path);
    } else if (!g_foreground) {
        /* Daemon mode without -l: use syslog */
        openlog("iwand", LOG_PID | LOG_NDELAY, LOG_DAEMON);
        g_use_syslog = 1;
    }
}

static void log_deinit(void)
{
    if (g_logfp) { fclose(g_logfp); g_logfp = NULL; }
    if (g_use_syslog) { closelog(); g_use_syslog = 0; }
}

/* ──────────────────────────────────────────────────────────
 *  TUN interface
 * ────────────────────────────────────────────────────────── */

static int tun_open(const char *dev)
{
    int fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        log_msg("open /dev/net/tun failed: %s\n", strerror(errno));
        return -1;
    }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", dev);
    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        log_msg("TUNSETIFF failed: %s\n", strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

static int tun_set_ip(const char *dev, uint32_t ip, uint32_t mask)
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
        log_msg("SIOCSIFADDR failed: %s\n", strerror(errno));
        close(sockfd);
        return -1;
    }

    addr->sin_addr.s_addr = mask;
    if (ioctl(sockfd, SIOCSIFNETMASK, &ifr) < 0) {
        log_msg("SIOCSIFNETMASK failed: %s\n", strerror(errno));
        close(sockfd);
        return -1;
    }

    /* Read existing flags and add IFF_UP */
    ioctl(sockfd, SIOCGIFFLAGS, &ifr);
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0) {
        log_msg("SIOCSIFFLAGS UP failed: %s\n", strerror(errno));
        close(sockfd);
        return -1;
    }

    close(sockfd);
    return 0;
}

static int tun_set_mtu(const char *dev, int mtu)
{
    int sockfd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (sockfd < 0) return -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", dev);
    ifr.ifr_mtu = mtu;
    int ret = ioctl(sockfd, SIOCSIFMTU, &ifr);
    if (ret < 0)
        log_msg("SIOCSIFMTU(%d) failed: %s\n", mtu, strerror(errno));
    close(sockfd);
    return ret;
}

static void tun_clear_ip(const char *dev)
{
    int sockfd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (sockfd < 0) return;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", dev);

    /* Remove address */
    struct sockaddr_in *addr = (struct sockaddr_in *)&ifr.ifr_addr;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = 0;
    ioctl(sockfd, SIOCSIFADDR, &ifr);

    /* Bring interface down */
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", dev);
    ioctl(sockfd, SIOCGIFFLAGS, &ifr);
    ifr.ifr_flags &= ~(IFF_UP | IFF_RUNNING);
    ioctl(sockfd, SIOCSIFFLAGS, &ifr);
    close(sockfd);
}

/* ──────────────────────────────────────────────────────────
 *  UDP socket
 * ────────────────────────────────────────────────────────── */

static int udp_socket_create(void)
{
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    int optval = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    return fd;
}

/* ──────────────────────────────────────────────────────────
 *  Client state
 * ────────────────────────────────────────────────────────── */

typedef struct {
    uint8_t  state;
    uint8_t  encrypt;        /* server-confirmed encryption flag */
    uint8_t  peer_dup_pkt;   /* peerduppkt from OPENACK */
    uint32_t peer_ip;        /* assigned tunnel IP (network order) */
    uint32_t dns0;           /* DNS server 0 (network order) */
    uint32_t dns1;           /* DNS server 1 (network order) */
    uint16_t server_mtu;     /* MTU from server */
    uint16_t session_token;  /* token from OPENACK (wire bytes) */
    uint32_t session_id;     /* session ID from OPENACK (wire bytes) */
    uint8_t  xor_key[8];    /* XOR key for data encryption */
    char     server_domain[64]; /* if server is domain name */
    uint32_t server_addr;    /* resolved server IP (network order) */
    uint16_t server_port;    /* server port (host order) */
    int      udp_fd;
    int      tun_fd;
    /* timers (monotonic seconds) */
    uint32_t last_recv_time;
    uint32_t last_open_time;
    uint32_t echo_counter;
    /* statistics */
    uint32_t rx_pkts;
    uint32_t tx_pkts;
    uint32_t tun_rx;
    uint32_t tun_tx;
    /* echo delay tracking */
    uint32_t cur_delay;
    uint32_t min_delay;
    uint32_t max_delay;
    /* route magic */
    uint32_t rt_magic;
    /* segment routing AES keys */
    aes_key_t sr_decrypt_key;
    aes_key_t sr_encrypt_key;
    /* IP fragment reassembly slots */
    struct {
        uint8_t  buf[FRAG_BUF_SIZE];
        uint32_t timestamp;
        uint32_t id;
        uint16_t off;
        uint16_t len;
        uint8_t  in_use;
    } frags[FRAG_SLOTS];
} sdwan_client_t;

static sdwan_client_t g_clnt;
static volatile sig_atomic_t g_quit = 0;
static volatile sig_atomic_t g_reconnect = 0;
static uint8_t g_frag_content[4096]; /* reassembled packet output buffer */

static uint32_t mono_secs(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)ts.tv_sec;
}

static uint64_t mono_usecs(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ULL + ts.tv_nsec / 1000;
}

/* ──────────────────────────────────────────────────────────
 *  Protocol: packet signing & verification
 * ────────────────────────────────────────────────────────── */

/* Sign a packet: computes MD5(header[0:8] + "mw") and writes 16 bytes at header+8.
 * Returns pointer to first byte after the signature (header+24). */
static uint8_t *pkt_sign(uint8_t *pkt)
{
    md5_ctx_t ctx;
    md5_init(&ctx);
    md5_update(&ctx, pkt, HDR_SIZE);
    uint8_t magic[2] = { 0x6d, 0x77 }; /* "mw" */
    md5_update(&ctx, magic, 2);
    md5_final(pkt + HDR_SIZE, &ctx);
    return pkt + HDR_SIZE + SIGN_SIZE;
}

/* Verify packet signature. Returns 1 if valid, 0 if not. */
static int pkt_verify(const uint8_t *pkt, int pktlen)
{
    if (pktlen < HDR_SIZE + SIGN_SIZE) return 0;
    md5_ctx_t ctx;
    md5_init(&ctx);
    md5_update(&ctx, pkt, HDR_SIZE);
    uint8_t magic[2] = { 0x6d, 0x77 };
    md5_update(&ctx, magic, 2);
    uint8_t digest[16];
    md5_final(digest, &ctx);
    return memcmp(digest, pkt + HDR_SIZE, SIGN_SIZE) == 0;
}

/* ──────────────────────────────────────────────────────────
 *  Protocol: key derivation
 * ────────────────────────────────────────────────────────── */

static void derive_xor_key(sdwan_client_t *c)
{
    /* key = MD5(username + password)[0:8] */
    char buf[128];
    int len = snprintf(buf, sizeof(buf), "%s%s", g_cfg.username, g_cfg.password);
    uint8_t digest[16];
    md5_hash((uint8_t *)buf, len, digest);
    memcpy(c->xor_key, digest, 8);
}

/* ──────────────────────────────────────────────────────────
 *  Segment routing: key setup and decryption
 * ────────────────────────────────────────────────────────── */

static void sr_setup_keys(sdwan_client_t *c)
{
    if (g_cfg.sr_count == 0) return;

    /* Build key material: jhash of SR links + reversed links, mixed with SR password */
    /* Simplified: derive AES key from srpassword + sr_links via MD5 */
    uint8_t keybuf[128];
    int klen = 0;

    /* Copy SR password */
    int pwlen = strlen(g_cfg.sr_password);
    if (pwlen > 0) {
        memcpy(keybuf, g_cfg.sr_password, pwlen);
        klen = pwlen;
    }

    /* Append SR link data */
    int linkdata_len = g_cfg.sr_count * 4;
    if (klen + linkdata_len <= (int)sizeof(keybuf)) {
        memcpy(keybuf + klen, g_cfg.sr_links, linkdata_len);
        klen += linkdata_len;
    }

    /* Pad to 32 bytes for AES key */
    while (klen < 32) {
        keybuf[klen] = 0;
        klen++;
    }

    /* Set decrypt and encrypt keys based on mode */
    if (g_cfg.sr_encrypt_mode == 2) {
        log_msg("WARNING: AES-256 SR encryption not supported, using AES-128\n");
    }
    aes_set_decrypt_key(keybuf, &c->sr_decrypt_key);
    aes_set_encrypt_key(keybuf, &c->sr_encrypt_key);
}

static void sr_decrypt(sdwan_client_t *c, uint8_t *data, int len, const uint8_t *srhdr)
{
    int block_size = ((srhdr[2] & 0x7) == 1) ? 16 : 32;

    /* Only decrypt if length is block-aligned */
    if (len % block_size != 0) return;

    /* Decrypt in-place, block by block */
    for (int off = 0; off < len; off += block_size) {
        /* For AES-128 (block_size=16), decrypt one block */
        if (block_size == 16) {
            uint8_t tmp[16];
            aes_decrypt_block(data + off, tmp, &c->sr_decrypt_key);
            memcpy(data + off, tmp, 16);
        }
        /* AES-256 would need 2 blocks or a 256-bit implementation — not common */
    }
}


/* ──────────────────────────────────────────────────────────
 *  Protocol: build OPEN packet
 * ────────────────────────────────────────────────────────── */

static int build_open_pkt(sdwan_client_t *c, uint8_t *buf)
{
    uint8_t *p = buf;

    /* Header */
    p[0] = PKT_OPEN;
    p[1] = g_cfg.encrypt;  /* sid = encrypt flag */
    p[2] = 0; p[3] = 0;    /* token = 0 */
    p[4] = 0; p[5] = 0; p[6] = 0; p[7] = 0; /* session_id = 0 */

    /* Sign and get pointer past signature */
    uint8_t *tlv = pkt_sign(buf);

    /* TLV: type=3, len=4, value=MTU (2 bytes, big-endian) */
    *tlv++ = 3;
    *tlv++ = 4;
    *tlv++ = (g_cfg.mtu >> 8) & 0xff;
    *tlv++ = g_cfg.mtu & 0xff;

    /* TLV: type=1, len=strlen(user)+2, value=username */
    int ulen = strlen(g_cfg.username);
    *tlv++ = 1;
    *tlv++ = (uint8_t)(ulen + 2);
    memcpy(tlv, g_cfg.username, ulen);
    tlv += ulen;

    /* TLV: type=2, len=0x12 (18), value=AES-encrypted password */
    /* Key: MD5("mw" + username) */
    {
        uint8_t keybuf[2 + 32];
        keybuf[0] = 0x6d; keybuf[1] = 0x77; /* "mw" */
        memcpy(keybuf + 2, g_cfg.username, ulen);
        uint8_t md5digest[16];
        md5_hash(keybuf, 2 + ulen, md5digest);

        aes_key_t aeskey;
        aes_set_encrypt_key(md5digest, &aeskey);

        /* Password: zero-padded 16-byte block */
        uint8_t pass_block[16];
        memset(pass_block, 0, 16);
        int plen = strlen(g_cfg.password);
        memcpy(pass_block, g_cfg.password, plen > 16 ? 16 : plen);

        *tlv++ = 2;
        *tlv++ = 0x12; /* 2 + 16 = 18 */
        aes_encrypt_block(pass_block, tlv, &aeskey);
        tlv += 16;
    }

    /* TLV: type=8, len=3, value=encrypt_mode (if encryption enabled) */
    if (g_cfg.encrypt) {
        *tlv++ = 8;
        *tlv++ = 3;
        *tlv++ = g_cfg.encrypt;
    }

    /* TLV: type=0xa, pipeid (if nonzero) */
    if (g_cfg.pipeid || g_cfg.pipeidx) {
        uint32_t val = g_cfg.pipeid | ((uint32_t)g_cfg.pipeidx << 15);
        *tlv++ = 0x0a;
        *tlv++ = 4;  /* total TLV length: type(1) + len(1) + value(2) */
        *tlv++ = (val >> 8) & 0xff;
        *tlv++ = val & 0xff;
    }

    return (int)(tlv - buf);
}

/* ──────────────────────────────────────────────────────────
 *  Protocol: build ECHO_REQ packet
 * ────────────────────────────────────────────────────────── */

static int build_echo_req(sdwan_client_t *c, uint8_t *buf)
{
    /* Header */
    buf[0] = PKT_ECHOREQ;
    buf[1] = 0;
    memcpy(buf + 2, &c->session_token, 2);
    memcpy(buf + 4, &c->session_id, 4);

    /* Sign */
    uint8_t *p = pkt_sign(buf);

    /* Echo payload (24 bytes):
     * [0:8]   = timestamp (microseconds, for RTT calculation)
     * [8:12]  = cur_delay
     * [12:16] = min_delay
     * [16:20] = max_delay
     * [20:24] = padding (zeros) */
    uint64_t now = mono_usecs();
    memcpy(p, &now, 8); p += 8;
    memcpy(p, &c->cur_delay, 4); p += 4;
    memcpy(p, &c->min_delay, 4); p += 4;
    memcpy(p, &c->max_delay, 4); p += 4;
    memset(p, 0, 4); p += 4;

    /* Route tag (12 bytes): "TDR\0" + htonl(rt_magic) + zeros */
    *p++ = 'T'; *p++ = 'D'; *p++ = 'R'; *p++ = 0;
    uint32_t rtm_n = htonl(c->rt_magic);
    memcpy(p, &rtm_n, 4); p += 4;
    memset(p, 0, 4); p += 4;

    return (int)(p - buf); /* should be 0x3c = 60 bytes */
}

/* ──────────────────────────────────────────────────────────
 *  Protocol: send packet
 * ────────────────────────────────────────────────────────── */

static int send_to_server(sdwan_client_t *c, const uint8_t *pkt, int len)
{
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = c->server_addr;
    addr.sin_port = htons(c->server_port);

    int n = sendto(c->udp_fd, pkt, len, 0, (struct sockaddr *)&addr, sizeof(addr));
    if (n < 0)
        log_msg("sendto error: %s\n", strerror(errno));
    return n;
}

/* ──────────────────────────────────────────────────────────
 *  Protocol: handle OPENACK
 * ────────────────────────────────────────────────────────── */

static void run_script(const char *script, const char *event, sdwan_client_t *c)
{
    if (script[0] == '\0') return;
    if (access(script, X_OK) != 0) return;

    char ip_str[16], dns0_str[16], dns1_str[16], mtu_str[8];
    /* peer_ip/dns are stored as host-order big-endian integers from TLV parsing */
    snprintf(ip_str, sizeof(ip_str), "%u.%u.%u.%u",
             (c->peer_ip>>24)&0xff, (c->peer_ip>>16)&0xff,
             (c->peer_ip>>8)&0xff, c->peer_ip&0xff);
    snprintf(dns0_str, sizeof(dns0_str), "%u.%u.%u.%u",
             (c->dns0>>24)&0xff, (c->dns0>>16)&0xff,
             (c->dns0>>8)&0xff, c->dns0&0xff);
    snprintf(dns1_str, sizeof(dns1_str), "%u.%u.%u.%u",
             (c->dns1>>24)&0xff, (c->dns1>>16)&0xff,
             (c->dns1>>8)&0xff, c->dns1&0xff);
    snprintf(mtu_str, sizeof(mtu_str), "%d",
             c->server_mtu > 0 ? c->server_mtu : g_cfg.mtu);

    log_msg("running: %s %s %s %s %s %s %s\n",
            script, event, g_cfg.tun_name, ip_str, mtu_str, dns0_str, dns1_str);

    pid_t pid = fork();
    if (pid < 0) {
        log_msg("fork failed: %s\n", strerror(errno));
        return;
    }
    if (pid == 0) {
        /* Child: exec the script with arguments (no shell) */
        char *argv[] = {
            (char *)script, (char *)event, g_cfg.tun_name,
            ip_str, mtu_str, dns0_str, dns1_str, NULL
        };
        execv(script, argv);
        _exit(127);
    }
    /* Parent: wait for child */
    int status;
    waitpid(pid, &status, 0);
}

static int handle_openack(sdwan_client_t *c, const uint8_t *pkt, int pktlen)
{
    if (c->state != STATE_AUTH_SENT) return 0;

    /* Verify signature */
    if (!pkt_verify(pkt, pktlen)) {
        log_msg("OPENACK: signature verification failed\n");
        return 0;
    }

    /* Parse TLVs after header + signature */
    const uint8_t *p = pkt + HDR_SIZE + SIGN_SIZE;
    int remain = pktlen - HDR_SIZE - SIGN_SIZE;

    while (remain > 0) {
        if (remain < 2) break;
        uint8_t type = p[0];
        uint8_t tlen = p[1]; /* total TLV length including type+len */
        if (tlen < 2 || tlen > remain) break;
        int vlen = tlen - 2;
        const uint8_t *val = p + 2;

        switch (type) {
        case 3: /* MTU */
            if (vlen >= 2)
                c->server_mtu = ((uint16_t)val[0] << 8) | val[1];
            break;
        case 4: /* Peer IP */
            if (vlen >= 4)
                c->peer_ip = ((uint32_t)val[0]<<24)|((uint32_t)val[1]<<16)|
                             ((uint32_t)val[2]<<8)|val[3];
            break;
        case 5: /* DNS0 */
            if (vlen >= 4)
                c->dns0 = ((uint32_t)val[0]<<24)|((uint32_t)val[1]<<16)|
                           ((uint32_t)val[2]<<8)|val[3];
            break;
        case 6: /* DNS0 + DNS1 */
            if (vlen >= 4)
                c->dns0 = ((uint32_t)val[0]<<24)|((uint32_t)val[1]<<16)|
                           ((uint32_t)val[2]<<8)|val[3];
            if (vlen >= 8)
                c->dns1 = ((uint32_t)val[4]<<24)|((uint32_t)val[5]<<16)|
                           ((uint32_t)val[6]<<8)|val[7];
            break;
        case 7: /* peer dup pkt flag */
            if (vlen >= 1)
                c->peer_dup_pkt = val[0];
            break;
        case 8: /* encrypt flag */
            if (vlen >= 1)
                c->encrypt = val[0];
            break;
        default:
            break;
        }

        p += tlen;
        remain -= tlen;
    }

    /* Require peer IP to be present before establishing */
    if (c->peer_ip == 0) {
        log_msg("OPENACK: no peer IP in response, rejecting\n");
        return 0;
    }

    /* Transition to ESTABLISHED */
    c->state = STATE_ESTABLISHED;
    memcpy(&c->session_token, pkt + 2, 2); /* safe unaligned copy */
    memcpy(&c->session_id, pkt + 4, 4);    /* safe unaligned copy */
    c->last_recv_time = mono_secs();
    c->echo_counter = 0;

    /* Apply network configuration */
    uint16_t eff_mtu = g_cfg.mtu;
    if (c->server_mtu >= 68 && c->server_mtu < eff_mtu)
        eff_mtu = c->server_mtu;

    /* Set TUN IP and MTU — fail and reset if interface setup fails */
    uint32_t mask = htonl(0xffffff00); /* 255.255.255.0 */
    if (tun_set_ip(g_cfg.tun_name, htonl(c->peer_ip), mask) < 0 ||
        tun_set_mtu(g_cfg.tun_name, eff_mtu) < 0) {
        log_msg("OPENACK: TUN interface setup failed, resetting\n");
        c->state = STATE_CLOSED;
        return 0;
    }

    char ip_str[16];
    snprintf(ip_str, sizeof(ip_str), "%u.%u.%u.%u",
             (c->peer_ip>>24)&0xff, (c->peer_ip>>16)&0xff,
             (c->peer_ip>>8)&0xff, c->peer_ip&0xff);
    log_msg("ESTABLISHED: ip=%s mtu=%u encrypt=%c session=%u\n",
            ip_str, eff_mtu, c->encrypt ? 'Y' : 'N',
            (unsigned)c->session_token);

    /* Run up script */
    run_script(g_cfg.up_script, "up", c);
    return 1;
}

/* ──────────────────────────────────────────────────────────
 *  Protocol: handle IP fragment reassembly (type 0x21)
 *
 *  IPFRAG packet layout:
 *    [0:8]   sdwan header
 *    [8:24]  sdwan_ethpkt: [0:8]=id_lo, [8:12]=id_hi, [12:16]=bitfield
 *            bitfield: bit0=eop, bits2-14=fragoff, bits15-25=fraglen
 *    [24:…]  fragment data (fraglen bytes)
 * ────────────────────────────────────────────────────────── */

static void handle_ipfrag(sdwan_client_t *c, const uint8_t *pkt, int pktlen)
{
    if (c->state != STATE_ESTABLISHED) return;
    if (pktlen < HDR_SIZE + ETHPKT_SIZE) return;

    const uint8_t *ethpkt = pkt + HDR_SIZE;

    /* Fragment group ID (bytes 8-11 of ethpkt) */
    uint32_t frag_id;
    memcpy(&frag_id, ethpkt + 8, 4);

    /* Parse bitfield at ethpkt[12:16] (little-endian uint32) */
    uint32_t bf = ((uint32_t)ethpkt[12])       |
                  ((uint32_t)ethpkt[13] << 8)  |
                  ((uint32_t)ethpkt[14] << 16) |
                  ((uint32_t)ethpkt[15] << 24);
    int eop     = bf & 0x1;
    int fragoff = (bf >> 2) & 0x1fff;
    int fraglen = (bf >> 15) & 0x7ff;

    /* Validate total packet length */
    if (pktlen != fraglen + HDR_SIZE + ETHPKT_SIZE) return;
    if (fraglen == 0) return;

    const uint8_t *frag_data = pkt + HDR_SIZE + ETHPKT_SIZE;

    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint32_t now = (uint32_t)tv.tv_sec;

    /* Search for existing slot with matching id */
    int found = 0;
    for (int i = 0; i < FRAG_SLOTS; i++) {
        if (!c->frags[i].in_use || c->frags[i].id != frag_id) continue;

        /* Check timeout */
        if (now - c->frags[i].timestamp >= FRAG_TIMEOUT) {
            c->frags[i].in_use = 0;
            found = 1;
            break;
        }

        int total_len;

        if (eop == 0) {
            /* Not last fragment: new data first, then accumulated */
            total_len = c->frags[i].len + fraglen;
            if (total_len > (int)sizeof(g_frag_content)) { found = 1; break; }
            memset(g_frag_content, 0, sizeof(g_frag_content));
            memcpy(g_frag_content, frag_data, fraglen);
            memcpy(g_frag_content + fraglen, c->frags[i].buf, c->frags[i].len);
        } else {
            /* Last fragment: compute total from fragoff + fraglen */
            total_len = fragoff + fraglen;
            if (total_len < (int)c->frags[i].len)
                total_len = c->frags[i].len;
            if (total_len > (int)sizeof(g_frag_content)) { found = 1; break; }
            memset(g_frag_content, 0, sizeof(g_frag_content));
            if (c->frags[i].len <= (int)sizeof(g_frag_content))
                memcpy(g_frag_content, c->frags[i].buf, c->frags[i].len);
            if (fragoff + fraglen <= (int)sizeof(g_frag_content))
                memcpy(g_frag_content + fragoff, frag_data, fraglen);
        }

        if (eop) {
            /* Reassembly complete — decrypt if needed and write to TUN */
            if (pkt[0] == PKT_DATA_ENC)
                xor_encrypt(c->xor_key, g_frag_content, total_len);
            write(c->tun_fd, g_frag_content, total_len);
            c->tun_tx++;
            c->frags[i].in_use = 0;
        } else {
            /* Store accumulated data back to slot */
            if (total_len <= FRAG_BUF_SIZE) {
                memcpy(c->frags[i].buf, g_frag_content, total_len);
                c->frags[i].len = total_len;
            }
        }
        found = 1;
        break;
    }

    if (found) return;

    /* No matching slot — find an empty or expired one */
    int slot_idx = -1;
    for (int i = 0; i < FRAG_SLOTS; i++) {
        if (!c->frags[i].in_use || (now - c->frags[i].timestamp >= FRAG_TIMEOUT)) {
            slot_idx = i;
            break;
        }
    }
    if (slot_idx < 0) return;

    /* Initialize new slot */
    c->frags[slot_idx].in_use = 1;
    c->frags[slot_idx].id = frag_id;
    c->frags[slot_idx].timestamp = now;
    c->frags[slot_idx].off = fragoff;
    c->frags[slot_idx].len = fraglen;
    if (fraglen <= FRAG_BUF_SIZE)
        memcpy(c->frags[slot_idx].buf, frag_data, fraglen);
}

/* ──────────────────────────────────────────────────────────
 *  Protocol: handle incoming packets
 * ────────────────────────────────────────────────────────── */

static void handle_data(sdwan_client_t *c, const uint8_t *pkt, int pktlen)
{
    if (c->state != STATE_ESTABLISHED) return;
    if (pktlen <= HDR_SIZE) return;

    const uint8_t *payload = pkt + HDR_SIZE;
    int payload_len = pktlen - HDR_SIZE;

    uint8_t decrypted[MAX_PKT_SIZE];
    if (payload_len > (int)sizeof(decrypted)) return;
    memcpy(decrypted, payload, payload_len);

    /* Decrypt if encrypted packet (original checks packet type only) */
    if (pkt[0] == PKT_DATA_ENC) {
        xor_encrypt(c->xor_key, decrypted, payload_len);
    }

    /* Write to TUN */
    int n = write(c->tun_fd, decrypted, payload_len);
    if (n > 0) c->tun_tx++;
}

static int handle_echo_resp(sdwan_client_t *c, const uint8_t *pkt, int pktlen)
{
    if (c->state != STATE_ESTABLISHED) return 0;
    if (!pkt_verify(pkt, pktlen)) return 0;

    /* Calculate delay from timestamp in echo response */
    uint64_t now = mono_usecs();
    if (pktlen >= (int)(HDR_SIZE + SIGN_SIZE + 8)) {
        uint64_t sent_time;
        memcpy(&sent_time, pkt + HDR_SIZE + SIGN_SIZE, 8);
        uint32_t delay = (uint32_t)(now - sent_time);
        c->cur_delay = delay;
        if (delay > c->max_delay) c->max_delay = delay;
        if (delay < c->min_delay) c->min_delay = delay;
    }
    return 1;
}

static int handle_close(sdwan_client_t *c, const uint8_t *pkt, int pktlen)
{
    if (c->state != STATE_ESTABLISHED) return 0;
    if (!pkt_verify(pkt, pktlen)) return 0;

    log_msg("peer CLOSED\n");
    c->state = STATE_CLOSED;
    return 1;
}

static void handle_openrej(sdwan_client_t *c, const uint8_t *pkt, int pktlen)
{
    if (c->state != STATE_AUTH_SENT) return;
    log_msg("peer AUTH REJECTED\n");
    c->state = STATE_CLOSED; /* trigger reset on next timer tick */
}

/* ──────────────────────────────────────────────────────────
 *  Protocol: handle segment routing (type 0x27)
 *
 *  SEGRT packet layout after sdwan header:
 *    [0] nextid — next hop index in link chain
 *    [1] linkcnt — total links
 *    [2] encrypt_algo (lower 3 bits) + encrypt_padlen (upper 5 bits)
 *    [3] padding/flags
 *  Then: linkcnt * 4 bytes of link IPs
 *  Then: the inner payload (DATA or IPFRAG)
 * ────────────────────────────────────────────────────────── */

static void handle_segrt(sdwan_client_t *c, const uint8_t *pkt, int pktlen)
{
    if (c->state != STATE_ESTABLISHED) return;

    const uint8_t *base = pkt + HDR_SIZE; /* point past sdwan header */
    if (pktlen < HDR_SIZE + 4) return;    /* need at least srhdr */

    /* Parse SR header */
    uint8_t linkcnt = base[1];
    int sr_hdr_len = linkcnt * 4 + 4; /* 4 bytes header + 4 bytes per link */

    if (pktlen < HDR_SIZE + sr_hdr_len) return;

    const uint8_t *inner = pkt + HDR_SIZE + sr_hdr_len;
    int inner_len = pktlen - HDR_SIZE - sr_hdr_len;

    if (inner_len <= 0) return;

    /* Check if inner packet is IPFRAG (type 0x22 in SR context) */
    if (inner[0] == 0x22) {
        /* Pass inner packet directly to IPFRAG handler */
        handle_ipfrag(c, inner, inner_len);
        return;
    }

    /* Otherwise: treat as DATA, optionally decrypt */
    uint8_t decrypt_buf[MAX_PKT_SIZE];
    if (inner_len > (int)sizeof(decrypt_buf)) return;

    /* Validate inner_len has room for inner header */
    if (inner_len <= HDR_SIZE) return;

    const uint8_t *data_start = inner + HDR_SIZE; /* skip inner sdwan header */
    int data_len = inner_len - HDR_SIZE;
    memcpy(decrypt_buf, data_start, data_len);

    /* SR decrypt if SR encryption is configured */
    if (g_cfg.sr_count > 0 && g_cfg.sr_encrypt_mode > 0) {
        uint8_t encrypt_algo = base[2] & 0x7;
        if (encrypt_algo == g_cfg.sr_encrypt_mode) {
            sr_decrypt(c, decrypt_buf, data_len, base);
            /* Remove padding */
            uint8_t padlen = (base[2] >> 3) & 0x1f;
            if (padlen > 0 && padlen < data_len)
                data_len -= padlen;
        }
    }

    /* Write decrypted data to TUN */
    write(c->tun_fd, decrypt_buf, data_len);
    c->tun_tx++;
}

static void handle_recv(sdwan_client_t *c, const uint8_t *pkt, int pktlen)
{
    if (pktlen < HDR_SIZE) return;

    uint8_t pkt_type = pkt[0];
    c->rx_pkts++;

    /* DATA packets — original binary does NOT validate session on DATA,
     * only checks source IP:port (already done by caller). */
    if (pkt_type == PKT_DATA || pkt_type == PKT_DATA_ENC) {
        c->last_recv_time = mono_secs();
        handle_data(c, pkt, pktlen);
        return;
    }

    int accepted = 0;
    switch (pkt_type) {
    case PKT_OPENACK:
        accepted = handle_openack(c, pkt, pktlen);
        break;
    case PKT_OPENREJ:
        handle_openrej(c, pkt, pktlen);
        /* Don't update liveness — OPENREJ has no signature and should
         * not prevent AUTH_TIMEOUT from triggering reconnect/re-resolve */
        break;
    case PKT_ECHORESP:
        accepted = handle_echo_resp(c, pkt, pktlen);
        break;
    case PKT_CLOSE:
        accepted = handle_close(c, pkt, pktlen);
        break;
    case PKT_IPFRAG:
        handle_ipfrag(c, pkt, pktlen);
        accepted = 1; /* fragments don't have signatures */
        break;
    case PKT_SEGRT:
        handle_segrt(c, pkt, pktlen);
        accepted = 1;
        break;
    default:
        return; /* unknown type — don't update liveness */
    }

    /* Update liveness only after successful validation */
    if (accepted)
        c->last_recv_time = mono_secs();
}

/* ──────────────────────────────────────────────────────────
 *  Protocol: send TUN data to server
 * ────────────────────────────────────────────────────────── */

static void handle_tun_recv(sdwan_client_t *c)
{
    uint8_t buf[MAX_PKT_SIZE];
    /* Leave room for header at the beginning */
    int n = read(c->tun_fd, buf + HDR_SIZE, MAX_PKT_SIZE - HDR_SIZE);
    if (n <= 0) return;
    if (c->state != STATE_ESTABLISHED) return;

    c->tun_rx++;

    /* Build header */
    if (c->encrypt) {
        buf[0] = PKT_DATA_ENC;
        buf[1] = c->encrypt;
        xor_encrypt(c->xor_key, buf + HDR_SIZE, n);
    } else {
        buf[0] = PKT_DATA;
        buf[1] = 0;
    }
    memcpy(buf + 2, &c->session_token, 2);
    memcpy(buf + 4, &c->session_id, 4);

    send_to_server(c, buf, HDR_SIZE + n);
    c->tx_pkts++;
}

/* ──────────────────────────────────────────────────────────
 *  DNS resolution
 * ────────────────────────────────────────────────────────── */

static int resolve_server(sdwan_client_t *c)
{
    /* Fast path: try as numeric IP first */
    struct in_addr addr;
    if (inet_pton(AF_INET, g_cfg.server, &addr) == 1) {
        c->server_addr = addr.s_addr;
        c->server_domain[0] = '\0';
        return 0;
    }

    /* Domain name: resolve via getaddrinfo */
    snprintf(c->server_domain, sizeof(c->server_domain), "%s", g_cfg.server);
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    int ret = getaddrinfo(g_cfg.server, NULL, &hints, &res);
    if (ret != 0) {
        log_msg("DNS resolution failed for %s: %s\n", g_cfg.server, gai_strerror(ret));
        return -1;
    }

    struct sockaddr_in *sin = (struct sockaddr_in *)res->ai_addr;
    c->server_addr = sin->sin_addr.s_addr;
    freeaddrinfo(res);

    char ip_str[16];
    inet_ntop(AF_INET, &c->server_addr, ip_str, sizeof(ip_str));
    log_msg("resolved %s -> %s\n", g_cfg.server, ip_str);
    return 0;
}

/* ──────────────────────────────────────────────────────────
 *  State machine: reset
 * ────────────────────────────────────────────────────────── */

static void client_reset(sdwan_client_t *c)
{
    if (c->state == STATE_ESTABLISHED || c->state == STATE_CLOSED) {
        log_msg("connection %s, resetting\n",
                c->state == STATE_CLOSED ? "closed by peer" : "lost");
        tun_clear_ip(g_cfg.tun_name);
        run_script(g_cfg.down_script, "down", c);
    }

    /* Close and recreate UDP socket */
    if (c->udp_fd >= 0) {
        close(c->udp_fd);
        c->udp_fd = -1;
    }
    c->udp_fd = udp_socket_create();
    if (c->udp_fd < 0) {
        log_msg("socket reinit failed\n");
    }

    /* Reset session state */
    c->session_token = 0;
    c->session_id = 0;
    c->peer_ip = 0;
    c->dns0 = 0;
    c->dns1 = 0;

    /* Clear fragment reassembly slots */
    for (int i = 0; i < FRAG_SLOTS; i++)
        c->frags[i].in_use = 0;
    c->server_mtu = 0;
    c->encrypt = 0;
    c->peer_dup_pkt = 0;
    c->cur_delay = 0;
    c->min_delay = 5000000; /* 5 sec initial — updated downward by real measurements */
    c->max_delay = 0;
    c->echo_counter = 0;
    c->last_recv_time = 0;
    c->last_open_time = 0;

    /* Determine next state based on whether we have an IP or need DNS */
    if (c->server_domain[0] != '\0') {
        c->state = STATE_DNS_NEEDED;
    } else {
        c->state = STATE_IP_READY;
    }
}

/* ──────────────────────────────────────────────────────────
 *  State machine: timer tick (called every ~1 second)
 * ────────────────────────────────────────────────────────── */

static void timer_tick(sdwan_client_t *c)
{
    uint32_t now = mono_secs();

    if (c->udp_fd < 0) {
        c->udp_fd = udp_socket_create();
        if (c->udp_fd < 0) return;
    }

    switch (c->state) {
    case STATE_NOT_READY:
        break;

    case STATE_DNS_NEEDED:
        log_msg("resolving %s...\n", g_cfg.server);
        if (resolve_server(c) == 0) {
            c->state = STATE_IP_READY;
        }
        /* If DNS fails, stay in DNS_NEEDED; will retry next tick */
        break;

    case STATE_IP_READY: {
        char ip_str[16];
        inet_ntop(AF_INET, &c->server_addr, ip_str, sizeof(ip_str));
        log_msg("INIT peer %s:%u\n", ip_str, g_cfg.port);
        c->server_port = g_cfg.port;
        c->last_recv_time = now;
        c->last_open_time = 0;
        c->state = STATE_AUTH_SENT;
        /* Fall through to send first OPEN */
    }
    /* fall through */

    case STATE_AUTH_SENT:
        /* Check overall timeout */
        if (now - c->last_recv_time > AUTH_TIMEOUT) {
            log_msg("AUTH timeout\n");
            client_reset(c);
            break;
        }
        /* Send OPEN every AUTH_RETRY_INTERVAL seconds */
        if (now - c->last_open_time >= AUTH_RETRY_INTERVAL) {
            c->last_open_time = now;
            uint8_t buf[MAX_PKT_SIZE];
            int len = build_open_pkt(c, buf);
            log_msg("sending OPEN (%d bytes)\n", len);
            send_to_server(c, buf, len);
        }
        break;

    case STATE_ESTABLISHED:
        /* Check data timeout */
        if (now - c->last_recv_time > DATA_TIMEOUT) {
            log_msg("DATA timeout (last_recv=%u, now=%u)\n",
                    c->last_recv_time, now);
            client_reset(c);
            break;
        }
        /* Send ECHO every ECHO_INTERVAL ticks */
        c->echo_counter++;
        if ((c->echo_counter & 1) == 0) {
            uint8_t buf[MAX_PKT_SIZE];
            int len = build_echo_req(c, buf);
            send_to_server(c, buf, len);
        }
        break;

    case STATE_CLOSED:
        client_reset(c);
        break;

    default:
        client_reset(c);
        break;
    }
}

/* ──────────────────────────────────────────────────────────
 *  Signal handling
 * ────────────────────────────────────────────────────────── */

static void sig_handler(int signo)
{
    (void)signo;
    g_quit = 1;
}

static void sig_reconnect(int signo)
{
    (void)signo;
    g_reconnect = 1;
}

static void sig_segfault(int signo)
{
    /* SA_RESETHAND restores default handler, so re-raise produces core dump */
    raise(signo);
}

/* ──────────────────────────────────────────────────────────
 *  Daemonize
 * ────────────────────────────────────────────────────────── */

static void daemonize(void)
{
    pid_t pid = fork();
    if (pid < 0) exit(1);
    if (pid > 0) exit(0);
    setsid();
    chdir("/");
    umask(077);
    int fd = open("/dev/null", O_RDWR);
    if (fd >= 0) {
        dup2(fd, STDIN_FILENO);
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        if (fd > 2) close(fd);
    }
}

/* ──────────────────────────────────────────────────────────
 *  Usage / Version
 * ────────────────────────────────────────────────────────── */

static const char *default_cfg = "/etc/sdwan/iwan.conf";
static const char *default_log = "";

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [options]\n"
        "  -f <config file>  config filepath [default: %s]\n"
        "  -l <log file>     log filepath\n"
        "  -F                run in foreground (don't daemonize)\n"
        "  -h                display this\n"
        "  -v                version info\n",
        prog, default_cfg);
}

static void version(void)
{
    printf("iwand (OpenWrt reimplementation) built %s\n", __DATE__);
}

/* ──────────────────────────────────────────────────────────
 *  Main
 * ────────────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
    const char *cfg_path = default_cfg;
    const char *log_path = default_log;
    static char cfg_abspath[PATH_MAX];
    static char log_abspath[PATH_MAX];
    int opt;

    memset(&g_cfg, 0, sizeof(g_cfg));
    memset(&g_clnt, 0, sizeof(g_clnt));
    g_clnt.udp_fd = -1;
    g_clnt.tun_fd = -1;
    g_clnt.min_delay = 5000000;

    while ((opt = getopt(argc, argv, "f:l:hFv")) != -1) {
        switch (opt) {
        case 'f': cfg_path = optarg; break;
        case 'l': log_path = optarg; break;
        case 'F': g_foreground = 1; break;
        case 'v': version(); return 0;
        case 'h': default: usage(argv[0]); return 0;
        }
    }

    /* Resolve relative paths to absolute before daemonize (which does chdir "/") */
    if (cfg_path[0] != '/') {
        if (realpath(cfg_path, cfg_abspath))
            cfg_path = cfg_abspath;
    }
    if (log_path[0] && log_path[0] != '/') {
        if (realpath(log_path, log_abspath))
            log_path = log_abspath;
        else {
            /* Log file may not exist yet; build absolute path manually */
            char cwd[PATH_MAX];
            if (getcwd(cwd, sizeof(cwd))) {
                snprintf(log_abspath, sizeof(log_abspath), "%s/%s", cwd, log_path);
                log_path = log_abspath;
            }
        }
    }

    /* Daemonize before opening log */
    if (!g_foreground)
        daemonize();

    log_init(log_path);

    /* Load config */
    if (cfg_load(cfg_path) < 0) {
        log_msg("load config file error: %s\n", cfg_path);
        log_deinit();
        return 1;
    }
    if (!cfg_valid()) {
        log_deinit();
        return 1;
    }

    /* Signals */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sa.sa_handler = sig_reconnect;
    sigaction(SIGUSR1, &sa, NULL);
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);
    /* SIGSEGV: log then crash (SA_RESETHAND restores default after first call) */
    sa.sa_handler = sig_segfault;
    sa.sa_flags = SA_RESETHAND;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, NULL);

    /* Initialize TUN */
    g_clnt.tun_fd = tun_open(g_cfg.tun_name);
    if (g_clnt.tun_fd < 0) {
        log_msg("TUN init failed\n");
        log_deinit();
        return 1;
    }

    /* Derive encryption keys */
    derive_xor_key(&g_clnt);
    sr_setup_keys(&g_clnt);

    /* Resolve server and set initial state */
    g_clnt.server_port = g_cfg.port;
    if (resolve_server(&g_clnt) == 0) {
        g_clnt.state = STATE_IP_READY;
    } else {
        g_clnt.state = STATE_DNS_NEEDED;
    }

    /* Create UDP socket */
    g_clnt.udp_fd = udp_socket_create();
    if (g_clnt.udp_fd < 0) {
        log_msg("socket init failed\n");
        close(g_clnt.tun_fd);
        log_deinit();
        return 1;
    }

    log_msg("SD-WAN client started successfully\n");

    /* ── Main event loop ────────────────────────────────── */
    uint32_t last_tick = mono_secs();

    while (!g_quit) {
        /* Handle SIGUSR1 reconnect */
        if (g_reconnect) {
            g_reconnect = 0;
            log_msg("received SIGUSR1, triggering reconnect\n");
            client_reset(&g_clnt);
        }

        struct pollfd fds[2];
        int nfds = 0;

        if (g_clnt.tun_fd >= 0) {
            fds[nfds].fd = g_clnt.tun_fd;
            fds[nfds].events = POLLIN;
            nfds++;
        }
        if (g_clnt.udp_fd >= 0) {
            fds[nfds].fd = g_clnt.udp_fd;
            fds[nfds].events = POLLIN;
            nfds++;
        }

        int ret = poll(fds, nfds, 1000); /* 1 second timeout as timer */
        if (ret < 0) {
            if (errno == EINTR) continue;
            log_msg("poll error: %s\n", strerror(errno));
            break;
        }

        /* Handle I/O events */
        for (int i = 0; i < nfds; i++) {
            if (!(fds[i].revents & POLLIN)) continue;

            if (fds[i].fd == g_clnt.tun_fd) {
                handle_tun_recv(&g_clnt);
            } else if (fds[i].fd == g_clnt.udp_fd) {
                uint8_t buf[MAX_PKT_SIZE];
                struct sockaddr_in from;
                socklen_t fromlen = sizeof(from);
                int n = recvfrom(g_clnt.udp_fd, buf, sizeof(buf), 0,
                                 (struct sockaddr *)&from, &fromlen);
                if (n > 0) {
                    /* Verify source matches server */
                    if (from.sin_addr.s_addr == g_clnt.server_addr &&
                        ntohs(from.sin_port) == g_clnt.server_port) {
                        handle_recv(&g_clnt, buf, n);
                    }
                }
            }
        }

        /* Timer tick (every 1 second) */
        uint32_t now = mono_secs();
        if (now != last_tick) {
            last_tick = now;
            timer_tick(&g_clnt);
        }
    }

    /* Cleanup */
    log_msg("shutting down\n");
    if (g_clnt.state == STATE_ESTABLISHED)
        run_script(g_cfg.down_script, "down", &g_clnt);
    if (g_clnt.udp_fd >= 0) close(g_clnt.udp_fd);
    if (g_clnt.tun_fd >= 0) close(g_clnt.tun_fd);
    log_deinit();
    return 0;
}

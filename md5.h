#ifndef MD5_H
#define MD5_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/// Length of an MD5 digest in bytes
#define MD5_DIGEST_LENGTH 16

/// MD5 context structure
typedef struct {
    uint32_t state[4];   // A, B, C, D
    uint32_t count[2];   // number of bits, modulo 2^64 (low-order word first)
    uint8_t buffer[64];  // input buffer
} MD5_CTX;

// Functions you can call
void MD5_Init(MD5_CTX *ctx);
void MD5_Update(MD5_CTX *ctx, const uint8_t *input, size_t len);
void MD5_Final(uint8_t digest[MD5_DIGEST_LENGTH], MD5_CTX *ctx);

/**
 * @brief  Compute the MD5 digest of a null-terminated string.
 * @param  str  The input string to hash.
 * @return A pointer to a newly allocated buffer of size MD5_DIGEST_LENGTH
 *         containing the raw MD5 digest bytes. Caller must free() it.
 */
static inline uint8_t *md5String(const char *str) {
    MD5_CTX ctx;
    uint8_t *digest = (uint8_t*)malloc(MD5_DIGEST_LENGTH);
    if (!digest) return NULL;
    MD5_Init(&ctx);
    MD5_Update(&ctx, (const uint8_t*)str, strlen(str));
    MD5_Final(digest, &ctx);
    return digest;
}

/* ——— private implementation details below ——— */

/// Rotate x left n bits
#define MD5_ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

// Basic MD5 functions
#define F(x,y,z) (((x) & (y)) | (~(x) & (z)))
#define G(x,y,z) (((x) & (z)) | ((y) & ~(z)))
#define H(x,y,z) ((x) ^ (y) ^ (z))
#define I(x,y,z) ((y) ^ ((x) | ~(z)))

// Round transformations
#define FF(a,b,c,d,M,s,t) \
    (a) = (b) + MD5_ROTL((a) + F((b),(c),(d)) + (M) + (t), (s))
#define GG(a,b,c,d,M,s,t) \
    (a) = (b) + MD5_ROTL((a) + G((b),(c),(d)) + (M) + (t), (s))
#define HH(a,b,c,d,M,s,t) \
    (a) = (b) + MD5_ROTL((a) + H((b),(c),(d)) + (M) + (t), (s))
#define II(a,b,c,d,M,s,t) \
    (a) = (b) + MD5_ROTL((a) + I((b),(c),(d)) + (M) + (t), (s))

// Predefined shift amounts and constants from RFC 1321
static const uint32_t md5_init_state[4] = {
    0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
};
static const uint32_t md5_T[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

/**
 * @brief Process a 64-byte block.
 */
static void MD5_Transform(uint32_t state[4], const uint8_t block[64]) {
    uint32_t A = state[0], B = state[1], C = state[2], D = state[3], X[16];
    // decode block into 16 uint32_t words (little endian)
    for (int i = 0; i < 16; ++i) {
        X[i] = (uint32_t)block[i*4]
             | ((uint32_t)block[i*4+1] << 8)
             | ((uint32_t)block[i*4+2] << 16)
             | ((uint32_t)block[i*4+3] << 24);
    }
    // Round 1
    FF(A, B, C, D, X[ 0],  7, md5_T[ 0]);  FF(D, A, B, C, X[ 1], 12, md5_T[ 1]);
    FF(C, D, A, B, X[ 2], 17, md5_T[ 2]);  FF(B, C, D, A, X[ 3], 22, md5_T[ 3]);
    FF(A, B, C, D, X[ 4],  7, md5_T[ 4]);  FF(D, A, B, C, X[ 5], 12, md5_T[ 5]);
    FF(C, D, A, B, X[ 6], 17, md5_T[ 6]);  FF(B, C, D, A, X[ 7], 22, md5_T[ 7]);
    FF(A, B, C, D, X[ 8],  7, md5_T[ 8]);  FF(D, A, B, C, X[ 9], 12, md5_T[ 9]);
    FF(C, D, A, B, X[10], 17, md5_T[10]);  FF(B, C, D, A, X[11], 22, md5_T[11]);
    FF(A, B, C, D, X[12],  7, md5_T[12]);  FF(D, A, B, C, X[13], 12, md5_T[13]);
    FF(C, D, A, B, X[14], 17, md5_T[14]);  FF(B, C, D, A, X[15], 22, md5_T[15]);
    // Round 2
    GG(A, B, C, D, X[ 1],  5, md5_T[16]);  GG(D, A, B, C, X[ 6],  9, md5_T[17]);
    GG(C, D, A, B, X[11], 14, md5_T[18]);  GG(B, C, D, A, X[ 0], 20, md5_T[19]);
    GG(A, B, C, D, X[ 5],  5, md5_T[20]);  GG(D, A, B, C, X[10],  9, md5_T[21]);
    GG(C, D, A, B, X[15], 14, md5_T[22]);  GG(B, C, D, A, X[ 4], 20, md5_T[23]);
    GG(A, B, C, D, X[ 9],  5, md5_T[24]);  GG(D, A, B, C, X[14],  9, md5_T[25]);
    GG(C, D, A, B, X[ 3], 14, md5_T[26]);  GG(B, C, D, A, X[ 8], 20, md5_T[27]);
    GG(A, B, C, D, X[13],  5, md5_T[28]);  GG(D, A, B, C, X[ 2],  9, md5_T[29]);
    GG(C, D, A, B, X[ 7], 14, md5_T[30]);  GG(B, C, D, A, X[12], 20, md5_T[31]);
    // Round 3
    HH(A, B, C, D, X[ 5],  4, md5_T[32]);  HH(D, A, B, C, X[ 8], 11, md5_T[33]);
    HH(C, D, A, B, X[11], 16, md5_T[34]);  HH(B, C, D, A, X[14], 23, md5_T[35]);
    HH(A, B, C, D, X[ 1],  4, md5_T[36]);  HH(D, A, B, C, X[ 4], 11, md5_T[37]);
    HH(C, D, A, B, X[ 7], 16, md5_T[38]);  HH(B, C, D, A, X[10], 23, md5_T[39]);
    HH(A, B, C, D, X[13],  4, md5_T[40]);  HH(D, A, B, C, X[ 0], 11, md5_T[41]);
    HH(C, D, A, B, X[ 3], 16, md5_T[42]);  HH(B, C, D, A, X[ 6], 23, md5_T[43]);
    HH(A, B, C, D, X[ 9],  4, md5_T[44]);  HH(D, A, B, C, X[12], 11, md5_T[45]);
    HH(C, D, A, B, X[15], 16, md5_T[46]);  HH(B, C, D, A, X[ 2], 23, md5_T[47]);
    // Round 4
    II(A, B, C, D, X[ 0],  6, md5_T[48]);  II(D, A, B, C, X[ 7], 10, md5_T[49]);
    II(C, D, A, B, X[14], 15, md5_T[50]);  II(B, C, D, A, X[ 5], 21, md5_T[51]);
    II(A, B, C, D, X[12],  6, md5_T[52]);  II(D, A, B, C, X[ 3], 10, md5_T[53]);
    II(C, D, A, B, X[10], 15, md5_T[54]);  II(B, C, D, A, X[ 1], 21, md5_T[55]);
    II(A, B, C, D, X[ 8],  6, md5_T[56]);  II(D, A, B, C, X[15], 10, md5_T[57]);
    II(C, D, A, B, X[ 6], 15, md5_T[58]);  II(B, C, D, A, X[13], 21, md5_T[59]);
    II(A, B, C, D, X[ 4],  6, md5_T[60]);  II(D, A, B, C, X[11], 10, md5_T[61]);
    II(C, D, A, B, X[ 2], 15, md5_T[62]);  II(B, C, D, A, X[ 9], 21, md5_T[63]);

    state[0] += A;
    state[1] += B;
    state[2] += C;
    state[3] += D;
    // zeroize sensitive data
    memset(X, 0, sizeof(X));
}

void MD5_Init(MD5_CTX *ctx) {
    ctx->state[0] = md5_init_state[0];
    ctx->state[1] = md5_init_state[1];
    ctx->state[2] = md5_init_state[2];
    ctx->state[3] = md5_init_state[3];
    ctx->count[0] = ctx->count[1] = 0;
}

void MD5_Update(MD5_CTX *ctx, const uint8_t *input, size_t len) {
    size_t index = (ctx->count[0] >> 3) & 0x3F;
    uint32_t part_len = 64 - index;
    uint32_t i = 0;

    // update bit count
    uint32_t bits = (uint32_t)(len << 3);
    ctx->count[1] += (uint32_t)(len >> 29);
    ctx->count[0] += bits;

    if (len >= part_len) {
        memcpy(&ctx->buffer[index], input, part_len);
        MD5_Transform(ctx->state, ctx->buffer);
        for (i = part_len; i + 63 < len; i += 64)
            MD5_Transform(ctx->state, &input[i]);
        index = 0;
    }
    else {
        i = 0;
    }
    memcpy(&ctx->buffer[index], &input[i], len - i);
}

void MD5_Final(uint8_t digest[MD5_DIGEST_LENGTH], MD5_CTX *ctx) {
    uint8_t bits[8];
    // save number of bits
    for (int i = 0; i < 4; ++i) {
        bits[i]   = (uint8_t)(ctx->count[0] >> (i * 8));
        bits[i+4] = (uint8_t)(ctx->count[1] >> (i * 8));
    }
    // pad out to 56 mod 64
    static const uint8_t PADDING[64] = { 0x80 };
    size_t index = (ctx->count[0] >> 3) & 0x3f;
    size_t pad_len = (index < 56) ? (56 - index) : (120 - index);
    MD5_Update(ctx, PADDING, pad_len);
    // append length (before padding)
    MD5_Update(ctx, bits, 8);
    // output digest
    for (int i = 0; i < 4; ++i) {
        digest[i*4]     = (uint8_t)(ctx->state[i] & 0xff);
        digest[i*4 + 1] = (uint8_t)((ctx->state[i] >> 8) & 0xff);
        digest[i*4 + 2] = (uint8_t)((ctx->state[i] >> 16) & 0xff);
        digest[i*4 + 3] = (uint8_t)((ctx->state[i] >> 24) & 0xff);
    }
    // zeroize sensitive data
    memset(ctx, 0, sizeof(*ctx));
}

#endif /* MD5_H */
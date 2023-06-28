/*
 * @file: sm4_impl.c
 * @description: implement SMS4 algorithm
 * @author: liuwei
 * @date: 2012/11/20
 * Copyright(C)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "smsoft.h"

#if defined(_MSC_VER) && defined(_MIPS_) && (_MSC_VER/100==12)
/* suppress "too big too optimize" warning */
#pragma warning(disable:4959)
#endif

#define SM4_DEBUG 0

/*** Macro definitions *********************************/
/* define L_R for rotating left */
#define L_R(x, k)   (((x) << (k)) | ((x) >> (32 - (k))))
#define M_Sbox_(s)  (SM4_SboxTable_[s])

#define M_w_b(w, b) ((sm4_word_t)(M_Sbox_((unsigned char)(((w) >> (b)) & 0x00FF)) << (b)))

#define M_t_(w) (M_w_b(w, 0) | M_w_b(w, 8) | M_w_b(w, 16) | M_w_b(w, 24))

#define M_L_(b) (((b)^(L_R(b, 2))^(L_R(b, 10))^(L_R(b, 18))^(L_R(b, 24))))

#define SM4_Lt(w)  (M_L_(M_t_(w)))

#define M_Lp_(b)   ((b) ^ L_R(b, 13) ^ L_R(b, 23))

#define SM4_Lpt(w) (M_Lp_(M_t_(w)))

#define F_rk_(x0, x1, x2, x3, rk) (x0) ^ SM4_Lt((x1)^(x2)^(x3)^(rk))

static unsigned char SM4_SboxTable_[256] = {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
};

/* System parameter */
static sm4_word_t SM4_FK_[4] = {0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc};

/* fixed parameter */
static sm4_word_t SM4_CK_[32] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};

static void sm4_get_rk(sm4_word_t mkey[4], sm4_word_t rk[32], int reverse)
{
    sm4_word_t k[36];
    sm4_word_t i = 0;

    k[0] = mkey[0] ^ SM4_FK_[0];
    k[1] = mkey[1] ^ SM4_FK_[1];
    k[2] = mkey[2] ^ SM4_FK_[2];
    k[3] = mkey[3] ^ SM4_FK_[3];

    for (i = 0; i < 32; ++i) {
        sm4_word_t t0 = k[i+1] ^ k[i+2] ^ k[i+3] ^ SM4_CK_[i];
        sm4_word_t t1 = M_t_(t0);
        k[i+4] = k[i] ^ M_Lp_(t1); /* SM4_Lpt(t0) */
        rk[i] = k[i+4];
#if SM4_DEBUG
        printf("rk[%2d] = %08x\n", i, enckey[i]);
#endif
    }

    if (reverse) {
        for (i = 0; i < 32; ++i) {
            rk[i] = k[35 - i];
        }
    }
}

static void sm4_block_1(sm4_word_t inblock[4], sm4_word_t outblock[4],
                        sm4_word_t rk[32])
{
    sm4_word_t X[36];
    int        i;
    sm4_word_t t0, t1;

    X[0] = inblock[0];
    X[1] = inblock[1];
    X[2] = inblock[2];
    X[3] = inblock[3];

    for (i = 0; i < 32; ++i) {
        t0 = X[i+1] ^ X[i+2] ^ X[i+3] ^ rk[i];
        t1 = M_t_(t0);
        X[i+4] = X[i] ^ M_L_(t1);
#if SM4_DEBUG
        printf("X[%2d] = %08x\n", i, X[i+4]);
#endif
    }

    outblock[0] = X[35];
    outblock[1] = X[34];
    outblock[2] = X[33];
    outblock[3] = X[32];
}

/********************************************/
#define BUFFER_TO_WORD(pp, iblock, k) \
        for (k = 0; k < 4; ++k) {\
            iblock[k] = (pp[0] << 24) | (pp[1] << 16) | (pp[2] << 8) | pp[3];\
            pp += 4;\
        }
#define WORD_TO_BUFFER(opp, oblock, k) \
        for (k = 0; k < 4; ++k) {\
            opp[0] = (oblock[k] >> 24) & 0x0ff;\
            opp[1] = (oblock[k] >> 16) & 0x0ff;\
            opp[2] = (oblock[k] >>  8) & 0x0ff;\
            opp[3] = (oblock[k] >>  0) & 0x0ff;\
            opp += 4;\
        }
/********************************************/

int sm4_encrypt_ecb(int mode, unsigned char *skey, int klen,
                unsigned char *indata, int inlen,
                unsigned char *outdata, int outlen)
{
    int do_last, k, m;

    int b_count = inlen / SM4_BLOCK_SIZE;
    int b_left = inlen - (b_count * SM4_BLOCK_SIZE);
    int b_padding = SM4_BLOCK_SIZE - b_left;

    sm4_word_t mkey[4], rk[32], iblock[4], oblock[4];
    unsigned char *pp, *opp, last_block[SM4_BLOCK_SIZE];

    /* calculate blocks */
    if (((mode == SM4_MODE_PADDING) && (outlen < inlen + (SM4_BLOCK_SIZE - b_left))) ||
        ((mode == SM4_MODE_NOPADDING) && (outlen < inlen) && (b_left != 0)) ||
        (inlen <= 0) || (outlen <= 0) || (klen != SM4_BLOCK_SIZE) ||
        (indata == NULL) || (outdata == NULL)) {
        /* no enough buffer */
        return SMX_INVALID_ARGS;
    }

    /* get rk */
    pp = skey;
    BUFFER_TO_WORD(pp, mkey, k)
    sm4_get_rk(mkey, rk, 0);

    do_last = 0;
    pp = indata;
    opp = outdata;
    for (m = 0; m < b_count; ++m) {
last_padding:
        BUFFER_TO_WORD(pp, iblock, k)
        /* encrypt */
        sm4_block_1(iblock, oblock, rk);
        /* transfer to output buffer */
        WORD_TO_BUFFER(opp, oblock, k)
    }

    /* last padding */
    if ((mode == SM4_MODE_PADDING) && !do_last) {
        memcpy(last_block, pp, b_left);
        memset(&last_block[b_left], b_padding, b_padding);
        pp = last_block;
        do_last = 1;
        goto last_padding;
    }

    /* must be padding-ed ? */
    return (opp - outdata);
}

int sm4_decrypt_ecb(int mode, unsigned char *skey, int klen,
                unsigned char *indata, int inlen,
                unsigned char *outdata, int outlen)
{
    int dec_len, k, m;

    int b_count = inlen / SM4_BLOCK_SIZE;
    int b_left = inlen - (b_count * SM4_BLOCK_SIZE);
    int b_padding;

    sm4_word_t mkey[4], rk[32], iblock[4], oblock[4];
    unsigned char *pp, *opp;

    if ((b_left != 0) || (outlen < inlen) || !indata || !outdata ||
        (inlen <= 0) || (outlen <= 0) || (klen != SM4_BLOCK_SIZE)) {
            return SMX_INVALID_ARGS;
    }

    /* get rk */
    pp = skey;
    BUFFER_TO_WORD(pp, mkey, k)
    sm4_get_rk(mkey, rk, 1);

    pp = indata;
    opp = outdata;
    for (m = 0; m < b_count; ++m) {
        BUFFER_TO_WORD(pp, iblock, k)
        /* decrypt */
        sm4_block_1(iblock, oblock, rk);
        /* transfer to output buffer */
        WORD_TO_BUFFER(opp, oblock, k)
    }
    dec_len = opp - outdata;

    /* last padding */
    if (mode == SM4_MODE_PADDING) {
        b_padding = *(opp - 1);
        if (b_padding > SM4_BLOCK_SIZE)
            return SMX_ERR_SM4_PADDING_SIZE;
        dec_len -= b_padding;
        opp -= b_padding;
        for (k = 0; k < b_padding; ++k) {
            if (opp[k] != b_padding)
                return SMX_ERR_SM4_PADDING_CRC;
        }
    }

    /* must be padding-ed ? */
    return dec_len;
}

/* =======================
 * (IVi XOR Bi) =>Bi'
 * C(Bi') -> IVi', Ci
 * IV0 <= IV 
 */
int sm4_encrypt_cbc(int mode, unsigned char *skey, int klen,
                    unsigned char *iv, int ivlen,
                    unsigned char *indata, int inlen,
                    unsigned char *outdata, int outlen)
{
    int do_last, k, m;

    int b_count = inlen / SM4_BLOCK_SIZE;
    int b_left = inlen - (b_count * SM4_BLOCK_SIZE);
    int b_padding = SM4_BLOCK_SIZE - b_left;

    sm4_word_t mkey[4], rk[32], iblock[4], oblock[4];
    unsigned char *pp, *opp, last_block[SM4_BLOCK_SIZE];

    /* calculate blocks */
   
    if (((mode == SM4_MODE_PADDING) && (outlen < inlen + (SM4_BLOCK_SIZE - b_left))) ||
        ((mode == SM4_MODE_NOPADDING) && (outlen < inlen) && (b_left != 0)) ||
        (inlen <= 0) || (outlen <= 0) || (klen != SM4_BLOCK_SIZE) ||
        (!iv || ivlen != SM4_BLOCK_SIZE) ||
        (indata == NULL) || (outdata == NULL)) {
        /* no enough buffer */
        return SMX_INVALID_ARGS;
    }

    /* get rk */
    pp = skey;
    BUFFER_TO_WORD(pp, mkey, k);
    sm4_get_rk(mkey, rk, 0);

    /* iv block */
    pp = iv;
    BUFFER_TO_WORD(pp, oblock, k);

    /* do encrypt */
    do_last = 0;
    pp = indata;
    opp = outdata;
    for (m = 0; m < b_count; ++m) {
last_padding:
        BUFFER_TO_WORD(pp, iblock, k);
        /* XOR */
        iblock[0] ^= oblock[0];
        iblock[1] ^= oblock[1];
        iblock[2] ^= oblock[2];
        iblock[3] ^= oblock[3];

        /* encrypt */
        sm4_block_1(iblock, oblock, rk);
        /* transfer to output buffer */
        WORD_TO_BUFFER(opp, oblock, k)
    }

    /* last padding */
    if ((mode == SM4_MODE_PADDING) && !do_last) {
        memcpy(last_block, pp, b_left);
        memset(&last_block[b_left], b_padding, b_padding);
        pp = last_block;
        do_last = 1;
        goto last_padding;
    }

    /* must be padding-ed ? */
    return (opp - outdata);
}

int sm4_decrypt_cbc(int mode, unsigned char *skey, int klen,
                    unsigned char *iv, int ivlen,
                    unsigned char *indata, int inlen,
                    unsigned char *outdata, int outlen)
{
    int dec_len, k, m;

    int b_count = inlen / SM4_BLOCK_SIZE;
    int b_left = inlen - (b_count * SM4_BLOCK_SIZE);
    int b_padding;

    sm4_word_t mkey[4], rk[32], iblock[4], oblock[4], ivblock[4];
    sm4_word_t *v1, *v2, *vtemp;
    unsigned char *pp, *opp;

    if ((b_left != 0) || (outlen < inlen) ||
        !indata || !outdata || !iv || (ivlen != SM4_BLOCK_SIZE) ||
        (inlen <= 0) || (outlen <= 0) || (klen != SM4_BLOCK_SIZE)) {
            return SMX_INVALID_ARGS;
    }

    /* get rk */
    pp = skey;
    BUFFER_TO_WORD(pp, mkey, k);
    sm4_get_rk(mkey, rk, 1);

    /* iv block */
    pp = iv;
    BUFFER_TO_WORD(pp, ivblock, k);

    pp = indata;
    opp = outdata;
    v1 = ivblock;
    v2 = iblock;
    for (m = 0; m < b_count; ++m) {
        BUFFER_TO_WORD(pp, v2, k);

        /* decrypt */
        sm4_block_1(v2, oblock, rk);

        /* XOR */
        v1[0] ^= oblock[0];
        v1[1] ^= oblock[1];
        v1[2] ^= oblock[2];
        v1[3] ^= oblock[3];

        /* transfer to output buffer */
        WORD_TO_BUFFER(opp, v1, k)
        /* exchange V1 V2 */
        vtemp = v1;
        v1 = v2;
        v2 = vtemp;
    }
    dec_len = opp - outdata;

    /* last padding */
    if (mode == SM4_MODE_PADDING) {
        b_padding = *(opp - 1);
        if (b_padding > SM4_BLOCK_SIZE)
            return SMX_ERR_SM4_PADDING_SIZE;
        dec_len -= b_padding;
        opp -= b_padding;
        for (k = 0; k < b_padding; ++k) {
            if (opp[k] != b_padding)
                return SMX_ERR_SM4_PADDING_CRC;
        }
    }

    /* must be padding-ed ? */
    return dec_len;
}

/****************** init/update/final mode **********************/
#define SM4_MODE_ECB 0
#define SM4_MODE_CBC 1

int sm4_encrypt_init(int mode, unsigned char *skey, int klen,
                     unsigned char *iv, int ivlen, sm4_ctx_t *sctx)
{
    int k;

    sm4_word_t mkey[4];
    unsigned char *pp;

    /* calculate blocks */
    if ((klen != SM4_BLOCK_SIZE) || (iv && ivlen != SM4_BLOCK_SIZE) ||
        (sctx == NULL) || 
        (mode != 0 && mode != SM4_MODE_PADDING && mode != SM4_MODE_NOPADDING))
    {
        return SMX_INVALID_ARGS;
    }

    /* get rk */
    pp = skey;
    BUFFER_TO_WORD(pp, mkey, k);
    sm4_get_rk(mkey, sctx->rk, 0);

    sctx->encrypt = 1;
    sctx->emode = SM4_MODE_ECB;
    sctx->c_len = 0;

    /* iv block */
    if (iv) {
        pp = iv;
        BUFFER_TO_WORD(pp, sctx->iv, k);
        sctx->emode = SM4_MODE_CBC;
    }
    sctx->padding = mode;

    return SMX_OK;
}

int sm4_decrypt_init(int mode, unsigned char *skey, int klen,
                     unsigned char *iv, int ivlen, sm4_ctx_t *sctx)
{
    int k;

    sm4_word_t mkey[4];
    unsigned char *pp;

    /* calculate blocks */
    if ((klen != SM4_BLOCK_SIZE) || (iv && ivlen != SM4_BLOCK_SIZE) ||
        (sctx == NULL) || 
        (mode != 0 && mode != SM4_MODE_PADDING && mode != SM4_MODE_NOPADDING))
    {
        return SMX_INVALID_ARGS;
    }

    /* get rk */
    pp = skey;
    BUFFER_TO_WORD(pp, mkey, k);
    sm4_get_rk(mkey, sctx->rk, 1);

    sctx->encrypt = 0;
    sctx->emode = SM4_MODE_ECB;
    sctx->c_len = 0;

    /* iv block */
    if (iv) {
        pp = iv;
        BUFFER_TO_WORD(pp, sctx->iv, k);
        sctx->emode = SM4_MODE_CBC;
    }
    sctx->padding = mode;

    return SMX_OK;
}

static int sm4_crypt_update_pre(sm4_ctx_t *sctx,
                                unsigned char *indata, int inlen,
                                unsigned char *outdata, int outlen,
                                sm4_word_t *iblock, unsigned char **ppp)
{
    int k;
    unsigned char *pp;

    /* calculate blocks */
    if (!sctx || (inlen <= 0) || (outlen <= 0) || 
        (outlen < ((inlen + sctx->c_len) / SM4_BLOCK_SIZE) * SM4_BLOCK_SIZE) ||
        (indata == NULL) || (outdata == NULL)) {
        /* no enough buffer */
        return SMX_INVALID_ARGS;
    }

    if (sctx->c_len > 0) {
        /* has cache */
        int first_padding = SM4_BLOCK_SIZE - sctx->c_len;
        if (first_padding > inlen) {
            memcpy(&sctx->cache[sctx->c_len], indata, inlen);
            sctx->c_len += inlen;
            return 0; /* cached */
        }
        /* else, do first block */
        if (first_padding > 0) {
            memcpy(&sctx->cache[sctx->c_len], indata, first_padding);
            inlen -= first_padding;
            pp = sctx->cache;
            BUFFER_TO_WORD(pp, iblock, k);
            pp = indata + first_padding;
            sctx->c_len = 0; /* reset */

            if (!sctx->encrypt && inlen == 0) {
                sctx->c_len = SM4_BLOCK_SIZE;
            }
        } /* else, cached a whole block for decrypt */
        else /* first_padding == 0 */ {
            /* hit cache */
            pp = sctx->cache;
            BUFFER_TO_WORD(pp, iblock, k);
            pp = indata;
            sctx->c_len = 0; /* reset */
        }
    } else if (inlen < SM4_BLOCK_SIZE) {
        memcpy(&sctx->cache[0], indata, inlen);
        sctx->c_len = inlen;
        return 0; /* cached */
    } else /* inlen >= SM4_BLOCK_SIZE */ {
        /* first block */
        pp = indata;
        BUFFER_TO_WORD(pp, iblock, k);
        inlen -= SM4_BLOCK_SIZE;
        sctx->c_len = 0;
    }

    *ppp = pp;
    return inlen;
}

int sm4_encrypt_update(sm4_ctx_t *sctx,
                       unsigned char *indata, int inlen,
                       unsigned char *outdata, int outlen)
{
    int k, m;

    int b_count;
    int b_left;

    sm4_word_t *rk, iblock[4], *oblock;
    unsigned char *pp, *opp;

    inlen = sm4_crypt_update_pre(sctx, indata, inlen, outdata, outlen, iblock, &pp);
    if (inlen < 0) {
        return inlen;
    }
    if (inlen == 0 && sctx->c_len > 0) {
        return 0; /* cached hit */
    }
    /* indata is SM4_BLOCK_SIZE size, inlen == 0 && sctx->c_len == 0 */

    b_count = inlen / SM4_BLOCK_SIZE;
    b_left = inlen - (b_count * SM4_BLOCK_SIZE);

    rk = sctx->rk;
    oblock = sctx->iv;

    opp = outdata;
    if (sctx->emode == SM4_MODE_CBC) {
        /* CBC mode */
        /* XOR */
        iblock[0] ^= oblock[0];
        iblock[1] ^= oblock[1];
        iblock[2] ^= oblock[2];
        iblock[3] ^= oblock[3];
    }

    /* encrypt */
    sm4_block_1(iblock, oblock, rk);
    WORD_TO_BUFFER(opp, oblock, k);

    /* else ECB mode */
    for (m = 0; m < b_count; ++m) {
        /* encrypt */
        BUFFER_TO_WORD(pp, iblock, k);
        if (sctx->emode == SM4_MODE_CBC) {
            /* CBC mode */
            /* XOR */
            iblock[0] ^= oblock[0];
            iblock[1] ^= oblock[1];
            iblock[2] ^= oblock[2];
            iblock[3] ^= oblock[3];
        }
        sm4_block_1(iblock, oblock, rk);
        /* transfer to output buffer */
        WORD_TO_BUFFER(opp, oblock, k);
    } /* end for */

    sctx->c_len = b_left;
    if (b_left > 0) {
        memcpy(sctx->cache, pp, b_left);
    }

    /* must be padding-ed ? */
    return (opp - outdata);
}

int sm4_encrypt_final(sm4_ctx_t *sctx,
                      unsigned char *outdata, int outlen)
{
    if (!sctx || !outlen || outlen < SM4_BLOCK_SIZE) {
        return SMX_INVALID_ARGS;
    }

    if ((sctx->padding == SM4_MODE_NOPADDING) && sctx->c_len > 0) {
        return SMX_ERR_SM4_PADDING_SIZE;
    }

    /* last padding */
    if (sctx->padding == SM4_MODE_PADDING) {
        sm4_word_t *rk, iblock[4], *oblock;
        unsigned char *pp, *opp;
        unsigned int k;

        int b_padding = SM4_BLOCK_SIZE - sctx->c_len;

        memset(&sctx->cache[sctx->c_len], b_padding, b_padding);
        pp = sctx->cache;
        BUFFER_TO_WORD(pp, iblock, k);

        rk = sctx->rk;
        oblock = sctx->iv;

        opp = outdata;
        if (sctx->emode == SM4_MODE_CBC) {
            /* CBC mode */
            /* XOR */
            iblock[0] ^= oblock[0];
            iblock[1] ^= oblock[1];
            iblock[2] ^= oblock[2];
            iblock[3] ^= oblock[3];
        }

        /* encrypt */
        sm4_block_1(iblock, oblock, rk);
        WORD_TO_BUFFER(opp, oblock, k);

        return SM4_BLOCK_SIZE;
    }

    return 0;
}

int sm4_decrypt_update(sm4_ctx_t *sctx,
                       unsigned char *indata, int inlen,
                       unsigned char *outdata, int outlen)
{
    int k, m;

    int b_count;
    int b_left;

    sm4_word_t *rk, *piv, *iblock, iblock_[4], oblock[4];
    unsigned char *pp, *opp;

    /* calculate blocks */
    iblock = iblock_;
    inlen = sm4_crypt_update_pre(sctx, indata, inlen, outdata, outlen, iblock, &pp);
    if (inlen < 0) {
        return inlen;
    }
    if (inlen == 0) {
        if (sctx->c_len > 0) {
            return 0; /* cached hit */
        } else if (sctx->c_len == 0) {
            /* cache last block */
            memcpy(&sctx->cache[0], indata, SM4_BLOCK_SIZE);
            sctx->c_len = SM4_BLOCK_SIZE;
            return 0;
        }
    }
    /* indata is SM4_BLOCK_SIZE size, inlen == 0 && sctx->c_len == 0 */

    b_count = inlen / SM4_BLOCK_SIZE;
    b_left = inlen - (b_count * SM4_BLOCK_SIZE);
    if (b_left == 0) {
        /* cache last block */
        b_left = SM4_BLOCK_SIZE;
        -- b_count;
    }

    rk = sctx->rk;
    piv = sctx->iv;

    opp = outdata;

    /* decrypt */
    sm4_block_1(iblock, oblock, rk);

    if (sctx->emode == SM4_MODE_CBC) {
        /* CBC mode */
        /* XOR */
        oblock[0] ^= piv[0];
        oblock[1] ^= piv[1];
        oblock[2] ^= piv[2];
        oblock[3] ^= piv[3];
        piv = iblock;
        iblock = sctx->iv;
    }
    WORD_TO_BUFFER(opp, oblock, k);

    /* else ECB mode */
    for (m = 0; m < b_count; ++m) {
        /* encrypt */
        BUFFER_TO_WORD(pp, iblock, k);
        sm4_block_1(iblock, oblock, rk);

        if (sctx->emode == SM4_MODE_CBC) {
            /* CBC mode */
            sm4_word_t *pw;
            /* XOR */
            oblock[0] ^= piv[0];
            oblock[1] ^= piv[1];
            oblock[2] ^= piv[2];
            oblock[3] ^= piv[3];

            pw = piv;
            piv = iblock;
            iblock = pw;
        }
        /* transfer to output buffer */
        WORD_TO_BUFFER(opp, oblock, k);
    } /* end for */

    sctx->c_len = b_left;
    if (b_left > 0) {
        memcpy(sctx->cache, pp, b_left);
    }

    if (piv != sctx->iv) {
        sctx->iv[0] = piv[0];
        sctx->iv[1] = piv[1];
        sctx->iv[2] = piv[2];
        sctx->iv[3] = piv[3];
    }

    /* must be padding-ed ? */
    return (opp - outdata);
}

int sm4_decrypt_final(sm4_ctx_t *sctx,
                      unsigned char *outdata, int outlen)
{
    sm4_word_t *rk, iblock[4], oblock[4], *piv;
    unsigned char *pp, *opp;
    unsigned int k, dec_len;

    if (!sctx || !outlen || outlen < SM4_BLOCK_SIZE) {
        return SMX_INVALID_ARGS;
    }

    if (sctx->c_len != SM4_BLOCK_SIZE) {
        return SMX_ERR_SM4_PADDING_SIZE;
    }

    piv = sctx->iv;
    rk = sctx->rk;
    pp = sctx->cache;
    BUFFER_TO_WORD(pp, iblock, k);

    /* decrypt */
    sm4_block_1(iblock, oblock, rk);
    if (sctx->emode == SM4_MODE_CBC) {
        /* CBC mode */
        /* XOR */
        oblock[0] ^= piv[0];
        oblock[1] ^= piv[1];
        oblock[2] ^= piv[2];
        oblock[3] ^= piv[3];
    }

    opp = outdata;
    WORD_TO_BUFFER(opp, oblock, k);
    dec_len = SM4_BLOCK_SIZE;

    /* last padding */
    if (sctx->padding == SM4_MODE_PADDING) {
        unsigned int b_padding = *(opp - 1);
        if (b_padding > SM4_BLOCK_SIZE)
            return SMX_ERR_SM4_PADDING_SIZE;
        dec_len -= b_padding;
        opp -= b_padding;
        for (k = 0; k < b_padding; ++k) {
            if (opp[k] != b_padding)
                return SMX_ERR_SM4_PADDING_CRC;
        }
    }

    return dec_len;
}

/************ test suite case *******************************************/
#ifdef _DEBUG
static void sm4_test_1()
{
    sm4_word_t mk_[4] = {0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210};
    sm4_word_t rke[32];
    sm4_word_t pData[4] = { 0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210 };
    sm4_word_t oData[4], *p1, *p2, *ptemp;
    int k;

    sm4_get_rk(mk_, rke, 0);
    sm4_block_1(pData, oData, rke);
    for (k = 0; k < 32; ++k) {
        printf("rk[%2d] = %08x\n", k, rke[k]);
    }

    /* 1 million time encryption */
    p1 = pData;
    p2 = oData;
    for (k = 0; k < 1000000; ++k) {
        sm4_block_1(p1, p2, rke);
        ptemp = p1;
        p1 = p2;
        p2 = ptemp;
    }

    for (k = 0; k < 4; ++k) {
        printf("c[%2d] = %08x\n", k, p1[k]);
    }
}

static void sm4_test_2()
{
    unsigned char mk_[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                             0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    unsigned char pData[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                               0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    unsigned char oData[16], oiData[16];
    int rc, k = 0;

    /* encrypt */
    rc = sm4_encrypt_ecb(SM4_MODE_NOPADDING, mk_, sizeof(mk_), pData, sizeof(pData), oData, 16);
    if (rc < 0) {
        printf("sm4_encrypt_ecb -1: error(%d)\n", rc);
        return;
    }
#if SM4_DEBUG
    for (k = 0; k < rc; ++k) {
        printf("c[%2d] = %02x\n", k, oData[k]);
    }
#endif

    /* decrypt */
    rc = sm4_decrypt_ecb(SM4_MODE_NOPADDING, mk_, sizeof(mk_), oData, sizeof(oData), oiData, 16);
    if (rc < 0) {
        printf("sm4_decrypt_ecb -1: error(%d)\n", rc);
        return;
    }

#if SM4_DEBUG
    for (k = 0; k < rc; ++k) {
        printf("t[%2d] = %02x\n", k, oiData[k]);
    }
#endif

    if (memcmp(pData, oiData, sizeof(oData)) == 0) {
        printf("SM4 encrypt/decrypt is OK!\n");
    } else {
        printf("SM4 encrypt/decrypt is ERROR!\n");
    }
}

static void sm4_test_3()
{
    unsigned char mk_[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                             0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    unsigned char pData[32] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                               0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
                               /* 2 block */
                               0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                               0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    unsigned char oData[32], oiData[32];
    int rc, k = 0;

    /* encrypt */
    rc = sm4_encrypt_ecb(SM4_MODE_NOPADDING, mk_, sizeof(mk_),
                          pData, sizeof(pData), oData, sizeof(oData));
    if (rc < 0) {
        printf("sm4_encrypt_ecb -2: error(%d)\n", rc);
        return;
    }
#if SM4_DEBUG
    for (k = 0; k < rc; ++k) {
        printf("cc[%2d] = %02x\n", k, oData[k]);
    }
#endif

    /* decrypt */
    rc = sm4_decrypt_ecb(SM4_MODE_NOPADDING, mk_, sizeof(mk_),
                         oData, sizeof(oData), oiData, sizeof(oiData));
    if (rc < 0) {
        printf("sm4_decrypt_ecb -2: error(%d)\n", rc);
        return;
    }
#if SM4_DEBUG
    for (k = 0; k < rc; ++k) {
        printf("tt[%2d] = %02x\n", k, oiData[k]);
    }
#endif

    if (memcmp(pData, oiData, sizeof(oData)) == 0) {
        printf("SM4 encrypt/decrypt is OK!\n");
    } else {
        printf("SM4 encrypt/decrypt is ERROR!\n");
    }
}

static void sm4_test_4(int inlen)
{
    unsigned char mk_[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                             0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    unsigned char pData[32] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                               0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
                               /* 2 block */
                               0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                               0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    unsigned char oData[32], oiData[32];
    int rc, k = 0, declen;

    /* encrypt */
    declen = sm4_encrypt_ecb(SM4_MODE_PADDING, mk_, sizeof(mk_),
                          pData, inlen, oData, sizeof(oData));
    if (declen < 0) {
        printf("sm4_encrypt_ecb(%2d) -4: error(%d)\n", inlen, declen);
        return;
    }
#if SM4_DEBUG
    for (k = 0; k < rc; ++k) {
        printf("cc[%2d] = %02x\n", k, oData[k]);
    }
#endif

    /* decrypt */
    rc = sm4_decrypt_ecb(SM4_MODE_PADDING, mk_, sizeof(mk_),
                         oData, declen, oiData, sizeof(oiData));
    if (rc < 0) {
        printf("sm4_decrypt_ecb(%2d) -4: error(%d)\n", inlen, rc);
        return;
    }
#if SM4_DEBUG
    for (k = 0; k < rc; ++k) {
        printf("tt[%2d] = %02x\n", k, oiData[k]);
    }
#endif

    if ((inlen == rc) && memcmp(pData, oiData, rc) == 0) {
        printf("SM4(ecb) encrypt/decrypt(%2d) is OK!\n", inlen);
    } else {
        printf("SM4(ecb) encrypt/decrypt(%2d) is ERROR!\n", inlen);
    }
}

static void sm4_test_5(int inlen)
{
    unsigned char mk_[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                             0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    unsigned char pData[32] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                               0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
                               /* 2 block */
                               0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                               0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    unsigned char oData[64], oiData[32];
    int rc, k = 0, declen;

    /* encrypt */
    declen = sm4_encrypt_cbc(SM4_MODE_PADDING, mk_, sizeof(mk_), mk_, sizeof(mk_),
                             pData, inlen, oData, sizeof(oData));
    if (declen < 0) {
        printf("sm4_encrypt_cbc(%2d) -5: error(%d)\n", inlen, declen);
        return;
    }
#if SM4_DEBUG
    for (k = 0; k < rc; ++k) {
        printf("cc[%2d] = %02x\n", k, oData[k]);
    }
#endif

    /* decrypt */
    rc = sm4_decrypt_cbc(SM4_MODE_PADDING, mk_, sizeof(mk_), mk_, sizeof(mk_),
                         oData, declen, oiData, sizeof(oiData));
    if (rc < 0) {
        printf("sm4_decrypt_cbc(%2d) -5: error(%d)\n", inlen, rc);
        return;
    }
#if SM4_DEBUG
    for (k = 0; k < rc; ++k) {
        printf("tt[%2d] = %02x\n", k, oiData[k]);
    }
#endif

    if ((inlen == rc) && memcmp(pData, oiData, rc) == 0) {
        printf("SM4(cbc) encrypt/decrypt(%2d) is OK!\n", inlen);
    } else {
        printf("SM4(cbc) encrypt/decrypt(%2d) is ERROR!\n", inlen);
    }
}

static int sm4_test_iuf(int padding, int cbc, int inlen)
{
    unsigned char mk_[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                             0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    unsigned char pData[1248] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                               0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
                               /* 2 block */
                               0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                               0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
                               /* 3 block */
                               0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                               0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
                               /* 4 block */
                               0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                               0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
    unsigned char oData[1248], oiData[1248], *ipp, *opp;
    int rc, k = 0, declen, m, enclen;

    sm4_ctx_t    sctx, sctxd;

    for (k = 64; k < sizeof(pData); ++k) {
        pData[k] = k % 128;
    }

    if (cbc) {
        sm4_encrypt_init(padding, mk_, sizeof(mk_), mk_, 16, &sctx);
        sm4_decrypt_init(padding, mk_, sizeof(mk_), mk_, 16, &sctxd);
    } else {
        sm4_encrypt_init(padding, mk_, sizeof(mk_), NULL, 0, &sctx);
        sm4_decrypt_init(padding, mk_, sizeof(mk_), NULL, 0, &sctxd);
    }

    /* encrypt */
    ipp = pData;
    opp = oData;

    for (m = 1; m <= inlen; ++m) {
        enclen = sm4_encrypt_update(&sctx, ipp, m, opp, sizeof(oData));
        if (enclen < 0) {
            printf("\tsm4_encrypt_update: error(%d)\n", enclen);
            return 0;
        }
        ipp += m;
        opp += enclen;
    }
    /* final */
    enclen = sm4_encrypt_final(&sctx, opp, 24);
    if (enclen < 0) {
        printf("\tsm4_encrypt_final: error(%d)\n", enclen);
        return 0;
    }
    opp += enclen;
    enclen = ipp - pData;
    declen = opp - oData;

#if 1
    printf("\tEncrypt Input length(%d), outlen(%d)\n", enclen, declen);

    /* decrypt */
    if (cbc) {
        rc = sm4_decrypt_cbc(padding, mk_, sizeof(mk_), mk_, 16, oData, declen, oiData, sizeof(oiData));
    } else {
        rc = sm4_decrypt_ecb(padding, mk_, sizeof(mk_), oData, declen, oiData, sizeof(oiData));
    }
    if (rc < 0) {
        printf("sm4_decrypt_ecb/cbc(%d): error(%d)\n", cbc, rc);
        return 0;
    }
    if ((enclen == rc) && memcmp(pData, oiData, rc) == 0) {
        printf("\t[1] SM4(cbc-iuf:%s-%s) encrypt/decrypt is OK!\n",
               padding ? "padding" : "no-padding",
               cbc ? "CBC" : "ECB");
    } else {
        printf("\t[1] SM4(cbc-iuf:%s-%s) encrypt/decrypt is Error!\n",
               padding ? "padding" : "no-padding",
               cbc ? "CBC" : "ECB");
        return 0;
    }
#endif

#if 1
    /* decrypt - iuf */
    ipp = oData;
    opp = oiData;
    for (m = 1; declen > m && declen > 0; ++m) {
        rc = sm4_decrypt_update(&sctxd, ipp, m, opp, sizeof(oiData));
        if (rc < 0) {
            printf("\tsm4_encrypt_update: error(%d)\n", rc);
            return 0;
        }
        ipp += m;
        declen -= m;
        opp += rc;
    }

    if (declen > 0) {
        rc = sm4_decrypt_update(&sctxd, ipp, declen, opp, sizeof(oiData));
        if (rc < 0) {
            printf("\tsm4_encrypt_update: error(%d)\n", rc);
            return 0;
        }
        ipp += declen;
        opp += rc;
    }

    /* final */
    rc = sm4_decrypt_final(&sctxd, opp, 24);
    if (rc < 0) {
        printf("\tsm4_decrypt_final: error(%d)\n", rc);
        return 0;
    }
    opp += rc;
    declen = opp - oiData;
    printf("\tDecrypt Input length(%d), outlen(%d)\n", ipp - oData, declen);

    if ((enclen == declen) && memcmp(pData, oiData, declen) == 0) {
        printf("\t[2] SM4(cbc-iuf:%s-%s) encrypt/decrypt is OK!\n",
               padding ? "padding" : "no-padding",
               cbc ? "CBC" : "ECB");
    } else {
        printf("\t[2] SM4(cbc-iuf:%s-%s) encrypt/decrypt is Error!\n",
               padding ? "padding" : "no-padding",
               cbc ? "CBC" : "ECB");
        return 0;
    }
#endif

    return 1;
}

static int sm4_test_iuf2(int padding, int cbc, int step)
{
    unsigned char mk_[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                             0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    unsigned char pData[1248] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                               0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
                               /* 2 block */
                               0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                               0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
                               /* 3 block */
                               0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                               0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
                               /* 4 block */
                               0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                               0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
    unsigned char oData[1248], oiData[1248], *ipp, *opp;
    int rc, k = 0, declen, m, enclen, total;

    sm4_ctx_t    sctx, sctxd;

    for (k = 64; k < sizeof(pData); ++k) {
        pData[k] = k % 128;
    }

    if (cbc) {
        sm4_encrypt_init(padding, mk_, sizeof(mk_), mk_, 16, &sctx);
        sm4_decrypt_init(padding, mk_, sizeof(mk_), mk_, 16, &sctxd);
    } else {
        sm4_encrypt_init(padding, mk_, sizeof(mk_), NULL, 0, &sctx);
        sm4_decrypt_init(padding, mk_, sizeof(mk_), NULL, 0, &sctxd);
    }

    /* encrypt */
    ipp = pData;
    opp = oData;

    total = sizeof(pData) - 32;
    for (m = step; m < total; m += step) {
        enclen = sm4_encrypt_update(&sctx, ipp, step, opp, sizeof(oData));
        if (enclen < 0) {
            printf("\tsm4_encrypt_update: error(%d)\n", enclen);
            return 0;
        }
        ipp += step;
        opp += enclen;
    }
    if (m < total) {
        m = total - m;
        enclen = sm4_encrypt_update(&sctx, ipp, m, opp, sizeof(oData));
        if (enclen < 0) {
            printf("\tsm4_encrypt_update: error(%d)\n", enclen);
            return 0;
        }
        ipp += m;
        opp += enclen;
    }

    /* final */
    enclen = sm4_encrypt_final(&sctx, opp, 24);
    if (enclen < 0) {
        printf("\tsm4_encrypt_final: error(%d)\n", enclen);
        return 0;
    }
    opp += enclen;
    enclen = ipp - pData;
    declen = opp - oData;

#if 0
    printf("\tEncrypt Input length(%d), outlen(%d)\n", enclen, declen);

    /* decrypt */
    if (cbc) {
        rc = sm4_decrypt_cbc(padding, mk_, sizeof(mk_), mk_, 16, oData, declen, oiData, sizeof(oiData));
    } else {
        rc = sm4_decrypt_ecb(padding, mk_, sizeof(mk_), oData, declen, oiData, sizeof(oiData));
    }
    if (rc < 0) {
        printf("sm4_decrypt_ecb/cbc(%d): error(%d)\n", cbc, rc);
        return 0;
    }
    if ((enclen == rc) && memcmp(pData, oiData, rc) == 0) {
        printf("\t[1] SM4(cbc-iuf:%s-%s) encrypt/decrypt is OK!\n",
               padding ? "padding" : "no-padding",
               cbc ? "CBC" : "ECB");
    } else {
        printf("\t[1] SM4(cbc-iuf:%s-%s) encrypt/decrypt is Error!\n",
               padding ? "padding" : "no-padding",
               cbc ? "CBC" : "ECB");
        return 0;
    }
#endif

#if 1
    /* decrypt - iuf */
    ipp = oData;
    opp = oiData;
    for (m = step; m < declen - step; m += step) {
        rc = sm4_decrypt_update(&sctxd, ipp, step, opp, sizeof(oiData));
        if (rc < 0) {
            printf("\tsm4_encrypt_update: error(%d)\n", rc);
            return 0;
        }
        ipp += step;
        opp += rc;
    }

    if (m < declen) {
        m = declen - m + step;
        rc = sm4_decrypt_update(&sctxd, ipp, m, opp, sizeof(oiData));
        if (rc < 0) {
            printf("\tsm4_encrypt_update: error(%d)\n", rc);
            return 0;
        }
        ipp += m;
        opp += rc;
    }

    /* final */
    rc = sm4_decrypt_final(&sctxd, opp, 24);
    if (rc < 0) {
        printf("\tsm4_decrypt_final: error(%d)\n", rc);
        return 0;
    }
    opp += rc;
    declen = opp - oiData;
    printf("\tDecrypt Input length(%d), outlen(%d)\n", ipp - oData, declen);

    if ((enclen == declen) && memcmp(pData, oiData, declen) == 0) {
        printf("\t[2] SM4(cbc-iuf:%s-%s) encrypt/decrypt is OK!\n",
               padding ? "padding" : "no-padding",
               cbc ? "CBC" : "ECB");
    } else {
        printf("\t[2] SM4(cbc-iuf:%s-%s) encrypt/decrypt is Error!\n",
               padding ? "padding" : "no-padding",
               cbc ? "CBC" : "ECB");
        return 0;
    }
#endif

    return 1;
}

void sm4_test()
{
    int  i = 0, rc = 0, k;

    sm4_test_2();
    sm4_test_3();
    for (i = 1; i < 32; ++i) {
        sm4_test_4(i);
        sm4_test_5(i);
    }

    k = 0;
    for (i = 1; i < SM4_BLOCK_SIZE * 3; ++i) {
        printf("i(%d) -> ", i);
        rc = sm4_test_iuf(1, 1, i);
        if (!rc) {
            ++k;
        }
    }
    printf("\nError counts(%d)\n", k);

    k = 0;
    for (i = 1; i <= SM4_BLOCK_SIZE; ++i) {
        printf("i(%d) -> ", i);
        rc = sm4_test_iuf2(1, 1, i);
        if (!rc) {
            ++k;
        }
    }
    printf("\nError counts(%d)\n", k);
}

#else /* _DEBUG */

void sm4_test()
{
}

#endif

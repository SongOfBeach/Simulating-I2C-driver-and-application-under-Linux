/*
 * @file: smsoft.h
 * @description: interface for SM2/SM3 algorithm
 * @author: liuwei
 * @date: 2011/07/09
 * Copyright(C)
 */

#ifndef _SMX_SOFT_IMPL_H_
#define _SMX_SOFT_IMPL_H_

#ifdef __cplusplus
extern "C" {
#endif
typedef struct sm4_ctx_t    sm4_ctx_t;

/** -- use word -- */

typedef unsigned char sm4_uchar_t;
typedef unsigned int  sm4_word_t;



/* SM4 const */
#define SM4_BLOCK_SIZE 16
#define SM4_MODE_PADDING   1
#define SM4_MODE_NOPADDING 2

struct sm4_ctx_t {
    unsigned char encrypt;
    unsigned char padding;
    unsigned char emode;
    unsigned char c_len;
    unsigned char cache[SM4_BLOCK_SIZE];
    sm4_word_t    rk[32];
    sm4_word_t    iv[4];
};

int sm4_encrypt_ecb(int mode, unsigned char *skey, int klen,
                unsigned char *indata, int inlen,
                unsigned char *outdata, int outlen);
int sm4_decrypt_ecb(int mode, unsigned char *skey, int klen,
                unsigned char *indata, int inlen,
                unsigned char *outdata, int outlen);
int sm4_encrypt_cbc(int mode, unsigned char *skey, int klen,
                    unsigned char *iv, int ivlen,
                    unsigned char *indata, int inlen,
                    unsigned char *outdata, int outlen);
int sm4_decrypt_cbc(int mode, unsigned char *skey, int klen,
                    unsigned char *iv, int ivlen,
                    unsigned char *indata, int inlen,
                    unsigned char *outdata, int outlen);

int sm4_encrypt_init(int mode, unsigned char *skey, int klen,
                     unsigned char *iv, int ivlen, sm4_ctx_t *sctx);
int sm4_encrypt_update(sm4_ctx_t *sctx,
                       unsigned char *indata, int inlen,
                       unsigned char *outdata, int outlen);
int sm4_encrypt_final(sm4_ctx_t *sctx,
                      unsigned char *outdata, int outlen);

int sm4_decrypt_init(int mode, unsigned char *skey, int klen,
                     unsigned char *iv, int ivlen, sm4_ctx_t *sctx);
int sm4_decrypt_update(sm4_ctx_t *sctx,
                       unsigned char *indata, int inlen,
                       unsigned char *outdata, int outlen);
int sm4_decrypt_final(sm4_ctx_t *sctx,
                      unsigned char *outdata, int outlen);

/* test suite */
int sm3_test_suite();
int sm2_ecdsa_test_suite();
int sm2_cipher_test_suite();
void sm4_test();

/** error code */
#define SMX_OK                   0
#define SMX_ERROR               -1
#define SMX_INVALID_KEY         -2
#define SMX_PRIVATE_KEY_INVALID -3
#define SMX_INVALID_ARGS        -4
#define SMX_BUFFER_TOO_SHORT    -5
#define SMX_MEMORY_OUT          -6
#define SMX_CTX_EMPTY           -7
#define SMX_ERR_SM4_DATA_LEN    -8
#define SMX_ERR_SM4_PADDING_SIZE -9
#define SMX_ERR_SM4_PADDING_CRC  -10


/* define error function */
#define ECDSA_F_SM2_DO_ENCRYPT  200
#define ECDSA_F_SM2_DO_DECRYPT  201
#define ECDSA_F_SM2_DO_DECRYPT  201

#ifdef __cplusplus
}
#endif

#endif /* _SMX_SOFT_IMPL_H_ */

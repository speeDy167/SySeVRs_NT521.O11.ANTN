/* ====================================================================
 * Copyright (c) 2001-2011 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 */
#include <openssl/opensslconf.h>
#ifndef OPENSSL_NO_AES
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <assert.h>
#include <openssl/aes.h>
#include "evp_locl.h"
#ifndef OPENSSL_FIPS
#include "modes_lcl.h"
#include <openssl/rand.h>
#include <sys/stat.h> 
#include <stdarg.h> 
#include <stonesoup/stonesoup_trace.h> 
#include <pthread.h> 
#include <semaphore.h> 
typedef struct {
AES_KEY ks;
block128_f block;
union {
cbc128_f cbc;
ctr128_f ctr;}stream;}EVP_AES_KEY;
typedef struct {
/* AES key schedule to use */
AES_KEY ks;
/* Set if key initialised */
int key_set;
/* Set if an iv is set */
int iv_set;
GCM128_CONTEXT gcm;
/* Temporary IV store */
unsigned char *iv;
/* IV length */
int ivlen;
int taglen;
/* It is OK to generate IVs */
int iv_gen;
/* TLS AAD length */
int tls_aad_len;
ctr128_f ctr;}EVP_AES_GCM_CTX;
typedef struct {
/* AES key schedules to use */
AES_KEY ks1;
AES_KEY ks2;
XTS128_CONTEXT xts;
void (*stream)(const unsigned char *, unsigned char *, size_t , const AES_KEY *, const AES_KEY *, const unsigned char [16]);}EVP_AES_XTS_CTX;
typedef struct {
/* AES key schedule to use */
AES_KEY ks;
/* Set if key initialised */
int key_set;
/* Set if an iv is set */
int iv_set;
/* Set if tag is valid */
int tag_set;
/* Set if message length set */
int len_set;
/* L and M parameters from RFC3610 */
int L;
int M;
CCM128_CONTEXT ccm;
ccm128_f str;}EVP_AES_CCM_CTX;
#define MAXBITCHUNK	((size_t)1<<(sizeof(size_t)*8-4))
#ifdef VPAES_ASM
extern int vpaes_set_encrypt_key(const unsigned char *userKey,int bits,AES_KEY *key);
extern int vpaes_set_decrypt_key(const unsigned char *userKey,int bits,AES_KEY *key);
extern void vpaes_encrypt(const unsigned char *in,unsigned char *out,const AES_KEY *key);
extern void vpaes_decrypt(const unsigned char *in,unsigned char *out,const AES_KEY *key);
extern void vpaes_cbc_encrypt(const unsigned char *in,unsigned char *out,size_t length,const AES_KEY *key,unsigned char *ivec,int enc);
#endif
#ifdef BSAES_ASM
extern void bsaes_cbc_encrypt(const unsigned char *in,unsigned char *out,size_t length,const AES_KEY *key,unsigned char ivec[16],int enc);
extern void bsaes_ctr32_encrypt_blocks(const unsigned char *in,unsigned char *out,size_t len,const AES_KEY *key,const unsigned char ivec[16]);
extern void bsaes_xts_encrypt(const unsigned char *inp,unsigned char *out,size_t len,const AES_KEY *key1,const AES_KEY *key2,const unsigned char iv[16]);
extern void bsaes_xts_decrypt(const unsigned char *inp,unsigned char *out,size_t len,const AES_KEY *key1,const AES_KEY *key2,const unsigned char iv[16]);
#endif
#ifdef AES_CTR_ASM
#endif
#ifdef AES_XTS_ASM
#endif
#if	defined(AES_ASM) && !defined(I386_ONLY) &&	(  \
	((defined(__i386)	|| defined(__i386__)	|| \
	  defined(_M_IX86)) && defined(OPENSSL_IA32_SSE2))|| \
	defined(__x86_64)	|| defined(__x86_64__)	|| \
	defined(_M_AMD64)	|| defined(_M_X64)	|| \
	defined(__INTEL__)				)
extern unsigned int OPENSSL_ia32cap_P[2];
#ifdef VPAES_ASM
#define VPAES_CAPABLE	(OPENSSL_ia32cap_P[1]&(1<<(41-32)))
#endif
#ifdef BSAES_ASM
#define BSAES_CAPABLE	VPAES_CAPABLE
#endif
/*
 * AES-NI section
 */
#define	AESNI_CAPABLE	(OPENSSL_ia32cap_P[1]&(1<<(57-32)))
extern int aesni_set_encrypt_key(const unsigned char *userKey,int bits,AES_KEY *key);
extern int aesni_set_decrypt_key(const unsigned char *userKey,int bits,AES_KEY *key);
extern void aesni_encrypt(const unsigned char *in,unsigned char *out,const AES_KEY *key);
extern void aesni_decrypt(const unsigned char *in,unsigned char *out,const AES_KEY *key);
extern void aesni_ecb_encrypt(const unsigned char *in,unsigned char *out,size_t length,const AES_KEY *key,int enc);
extern void aesni_cbc_encrypt(const unsigned char *in,unsigned char *out,size_t length,const AES_KEY *key,unsigned char *ivec,int enc);
extern void aesni_ctr32_encrypt_blocks(const unsigned char *in,unsigned char *out,size_t blocks,const void *key,const unsigned char *ivec);
extern void aesni_xts_encrypt(const unsigned char *in,unsigned char *out,size_t length,const AES_KEY *key1,const AES_KEY *key2,const unsigned char iv[16]);
extern void aesni_xts_decrypt(const unsigned char *in,unsigned char *out,size_t length,const AES_KEY *key1,const AES_KEY *key2,const unsigned char iv[16]);
extern void aesni_ccm64_encrypt_blocks(const unsigned char *in,unsigned char *out,size_t blocks,const void *key,const unsigned char ivec[16],unsigned char cmac[16]);
extern void aesni_ccm64_decrypt_blocks(const unsigned char *in,unsigned char *out,size_t blocks,const void *key,const unsigned char ivec[16],unsigned char cmac[16]);
int stoning_autoalarm = 0;
int stonesoup_global_variable;
void* stonesoup_printf_context = NULL;
void stonesoup_setup_printf_context() {
    struct stat st = {0};
    char * ss_tc_root = NULL;
    char * dirpath = NULL;
    int size_dirpath = 0;
    char * filepath = NULL;
    int size_filepath = 0;
    int retval = 0;
    ss_tc_root = getenv("SS_TC_ROOT");
    if (ss_tc_root != NULL) {
        size_dirpath = strlen(ss_tc_root) + strlen("testData") + 2;
        dirpath = (char*) malloc (size_dirpath * sizeof(char));
        if (dirpath != NULL) {
            sprintf(dirpath, "%s/%s", ss_tc_root, "testData");
            retval = 0;
            if (stat(dirpath, &st) == -1) {
                retval = mkdir(dirpath, 0700);
            }
            if (retval == 0) {
                size_filepath = strlen(dirpath) + strlen("logfile.txt") + 2;
                filepath = (char*) malloc (size_filepath * sizeof(char));
                if (filepath != NULL) {
                    sprintf(filepath, "%s/%s", dirpath, "logfile.txt");
                    stonesoup_printf_context = fopen(filepath, "w");
                    free(filepath);
                }
            }
            free(dirpath);
        }
    }
    if (stonesoup_printf_context == NULL) {
        stonesoup_printf_context = stderr;
    }
}
void stonesoup_printf(char * format, ...) {
    va_list argptr;
    va_start(argptr, format);
    vfprintf(stonesoup_printf_context, format, argptr);
    va_end(argptr);
    fflush(stonesoup_printf_context);
}
void stonesoup_close_printf_context() {
    if (stonesoup_printf_context != NULL &&
        stonesoup_printf_context != stderr) {
        fclose(stonesoup_printf_context);
    }
}
void cataclysmically_unreservedly(int menison_irradiative,... );
void spellbinder_snowland(void *henni_gestor);
struct stonesoup_data {
    int qsize;
    char *file1;
    char *file2;
    char *data;
    int data_size;
};
pthread_t stonesoup_t0, stonesoup_t1;
sem_t stonesoup_sem;
int stonesoup_comp (const void * a, const void * b)
{
    if (a > b) {
        return -1;
    }
    else if (a < b) {
        return 1;
    }
    else {
        return 0;
    }
}
int stonesoup_pmoc (const void * a, const void * b)
{
    return -1 * stonesoup_comp(a, b);
}
void stonesoup_readFile(char *filename) {
    FILE *fifo;
    char ch;
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpotXNPk_ss_testcase/src-rose/crypto/evp/e_aes.c", "stonesoup_readFile");
    fifo = fopen(filename, "r");
    if (fifo != NULL) {
        while ((ch = fgetc(fifo)) != EOF) {
            stonesoup_printf("%c", ch);
        }
        fclose(fifo);
    }
}
void *to1337(void *data) {
    struct stonesoup_data *stonesoupData = (struct stonesoup_data*)data;
    int qsize;
    int random;
    char temp;
    char *temp_str;
    int i = 0;
    int *stonesoup_arr;
    int semValue = 0;
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpotXNPk_ss_testcase/src-rose/crypto/evp/e_aes.c", "to1337");
    stonesoup_printf("Entering to1337\n");
    /* slow things down to make correct thing happen in good cases */
    stonesoup_arr = malloc(sizeof(int)*stonesoupData->qsize);
    if (stonesoup_arr != NULL) {
        for (i = 0; i < stonesoupData->qsize; i++) {
            stonesoup_arr[i] = stonesoupData->qsize - i;
        }
        qsort(stonesoup_arr, stonesoupData->qsize, sizeof(int), &stonesoup_comp);
        free (stonesoup_arr);
        stonesoup_arr = NULL;
    }
    temp_str = malloc(sizeof(char)*(stonesoupData->data_size + 1));
    qsize = stonesoupData->qsize;
    sem_getvalue(&stonesoup_sem, &semValue);
    tracepoint(stonesoup_trace, variable_signed_integral, "semaphore", semValue, &semValue, "to1337: Locking semaphore");
    tracepoint(stonesoup_trace, trace_point, "to1337: Locking semaphore");
    sem_wait(&stonesoup_sem);
    sem_getvalue(&stonesoup_sem, &semValue);
    tracepoint(stonesoup_trace, trace_point, "to1337: Locked semaphore");
    tracepoint(stonesoup_trace, variable_signed_integral, "semaphore", semValue, &semValue, "to1337: Locked semaphore");
    i = 0;
    while(stonesoupData->data[i] != '\0') {
        random = (int)(rand() / (double)RAND_MAX + 0.5); /* add .5 before truncation to round */
        switch(stonesoupData->data[i]) { /* 1337 s<r1p7 i5 f0r h4x0r5 */
            case 'c':
                if (random == 0)
                    temp = '<';
                else
                    temp = 'c';
                break;
            case 'e':
                if (random == 0)
                    temp = '3';
                else
                    temp = 'e';
                break;
            case 'i':
                if (random == 0)
                    temp = '1';
                else
                    temp = 'i';
                break;
            case 'l':
                if (random == 0)
                    temp = '1';
                else
                    temp = 'l';
                break;
            case 'o':
                if (random == 0)
                    temp = '0';
                else
                    temp = 'o';
                break;
            case 's':
                if (random == 0)
                    temp = '5';
                else
                    temp = 's';
                break;
            case 't':
                if (random == 0)
                    temp = '7';
                else
                    temp = 't';
                break;
            default:
                temp = stonesoupData->data[i];
                break;
        }
        temp_str[i] = temp;
        i++;
    }
    temp_str[i] = '\0';
    free(stonesoupData->data);
    stonesoupData->data = NULL; /* setting free()'d ptrs to null is good practice yo */
    tracepoint(stonesoup_trace, variable_address, "stonesoupData->data", stonesoupData->data, "TRIGGER-STATE: SET");
    stonesoup_printf("Set ptr to null\n");
    tracepoint(stonesoup_trace, trace_point, "to1337: Reading file");
    /* execute second */
    stonesoup_readFile(stonesoupData->file2);
    tracepoint(stonesoup_trace, trace_point, "to1337: Read file");
    stonesoup_printf("Set ptr to NON null\n");
    stonesoupData->data = temp_str;
    tracepoint(stonesoup_trace, variable_address, "stonesoupData->data", stonesoupData->data, "TRIGGER-STATE: UNSET");
    tracepoint(stonesoup_trace, trace_point, "to1337: Unlocking semaphore");
    sem_post(&stonesoup_sem);
    sem_getvalue(&stonesoup_sem, &semValue);
    tracepoint(stonesoup_trace, variable_signed_integral, "semaphore", semValue, &semValue, "to1337: Unlocked semaphore");
    tracepoint(stonesoup_trace, trace_point, "to1337: Unlocked semaphore");
    return NULL;
}
void *reverseStr(void * data) {
    struct stonesoup_data *stonesoupData = (struct stonesoup_data*)data;
    int i = 0;
    char *temp_str;
    int semValue = 0;
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpotXNPk_ss_testcase/src-rose/crypto/evp/e_aes.c", "reverseStr");
    stonesoup_printf("Entering reverseStr\n");
    /* execute first */
    stonesoup_readFile(stonesoupData->file1);
    sem_getvalue(&stonesoup_sem, &semValue);
    tracepoint(stonesoup_trace, variable_signed_integral, "semaphore", semValue, &semValue, "reverseStr: Locking semaphore");
    tracepoint(stonesoup_trace, trace_point, "reverseStr: Locking semaphore");
    sem_wait(&stonesoup_sem); /* if weakness has been triggered, */
                                                                    /* too many resource copies available */
    sem_getvalue(&stonesoup_sem, &semValue);
    tracepoint(stonesoup_trace, trace_point, "reverseStr: Locked semaphore");
    tracepoint(stonesoup_trace, variable_signed_integral, "semaphore", semValue, &semValue, "reverseStr: Locked semaphore");
    temp_str = malloc(sizeof(char)* (stonesoupData->data_size + 1));
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
    tracepoint(stonesoup_trace, variable_address, "stonesoupData->data", stonesoupData->data, "TRIGGER-STATE: ACCESS");
    for (i = 0; i < stonesoupData->data_size; i++) {
        /* STONESOUP: TRIGGER-POINT (multipleunlocks) */
        stonesoup_printf("Dereferencing ptr\n");
        temp_str[stonesoupData->data_size - 1 - i] = stonesoupData->data[i]; /* null ptr dereference */
    }
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
    temp_str[stonesoupData->data_size] = '\0';
    free(stonesoupData->data);
    stonesoupData->data = NULL;
    stonesoupData->data = temp_str;
    tracepoint(stonesoup_trace, trace_point, "reverseStr: Unlocking semaphore");
    sem_post(&stonesoup_sem);
    sem_getvalue(&stonesoup_sem, &semValue);
    tracepoint(stonesoup_trace, variable_signed_integral, "semaphore", semValue, &semValue, "reverseStr: Unlocked semaphore");
    tracepoint(stonesoup_trace, trace_point, "reverseStr: Unlocked semaphore");
    return NULL;
}
void toLower (struct stonesoup_data * stonesoupData) {
    int i = 0;
    int semValue = 0;
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpotXNPk_ss_testcase/src-rose/crypto/evp/e_aes.c", "toLower");
    sem_getvalue(&stonesoup_sem, &semValue);
    tracepoint(stonesoup_trace, variable_signed_integral, "semaphore", semValue, &semValue, "toLower: Locking semaphore");
    tracepoint(stonesoup_trace, trace_point, "toLower: Locking semaphore");
    sem_wait(&stonesoup_sem);
    stonesoup_printf("Entering toLower\n");
    sem_getvalue(&stonesoup_sem, &semValue);
    tracepoint(stonesoup_trace, trace_point, "toLower: Locked semaphore");
    tracepoint(stonesoup_trace, variable_signed_integral, "semaphore", semValue, &semValue, "toLower: Locked semaphore");
    for (i = 0; i < strlen(stonesoupData->data) - 1; i++) { /* all caps to lower */
        if (stonesoupData->data[i] >= 'A' &&
            stonesoupData->data[i] <= 'Z') {
            stonesoupData->data[i] += 32;
        }
    }
    tracepoint(stonesoup_trace, trace_point, "toLower: Unlocking semaphore (01)");
    sem_post(&stonesoup_sem);
    sem_getvalue(&stonesoup_sem, &semValue);
    tracepoint(stonesoup_trace, variable_signed_integral, "semaphore", semValue, &semValue, "toLower: Unlocked semaphore (01)");
    tracepoint(stonesoup_trace, trace_point, "toLower: Unlocked semaphore (01)");
    tracepoint(stonesoup_trace, trace_point, "toLower: CROSSOVER-POINT: BEFORE");
    tracepoint(stonesoup_trace, trace_point, "toLower: Unlocking semaphore (02)");
    /* STONESOUP: CROSSOVER-POINT (multipleunlocks) */
    sem_post(&stonesoup_sem); /* oops, extra unlock */
    sem_getvalue(&stonesoup_sem, &semValue);
    tracepoint(stonesoup_trace, variable_signed_integral, "semaphore", semValue, &semValue, "toLower: Unlocked semaphore (02)");
    tracepoint(stonesoup_trace, trace_point, "toLower: Unlocked semaphore (02)");
    tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
    tracepoint(stonesoup_trace, variable_signed_integral, "stonesoupData->qsize", stonesoupData->qsize, &(stonesoupData->qsize), "CROSSOVER-STATE");
    tracepoint(stonesoup_trace, variable_buffer, "stonesoupData->data", stonesoupData->data, "CROSSOVER-STATE");
    tracepoint(stonesoup_trace, variable_buffer, "stonesoupData->file1", stonesoupData->file1, "CROSSOVER-STATE");
    tracepoint(stonesoup_trace, variable_buffer, "stonesoupData->file2", stonesoupData->file2, "CROSSOVER-STATE");
}

static int aesni_init_key(EVP_CIPHER_CTX *ctx,const unsigned char *key,const unsigned char *iv,int enc)
{
  int ret;
  int mode;
  EVP_AES_KEY *dat = (EVP_AES_KEY *)(ctx -> cipher_data);
  mode = (ctx -> cipher -> flags & 0xF0007);
  if ((mode == 0x1 || mode == 0x2) && !enc) {
    ret = aesni_set_decrypt_key(key,ctx -> key_len * 8,(ctx -> cipher_data));
    dat -> block = ((block128_f )aesni_decrypt);
    dat -> stream . cbc = (mode == 0x2?((cbc128_f )aesni_cbc_encrypt) : ((void *)0));
  }
  else {
    ret = aesni_set_encrypt_key(key,ctx -> key_len * 8,(ctx -> cipher_data));
    dat -> block = ((block128_f )aesni_encrypt);
    if (mode == 0x2) {
      dat -> stream . cbc = ((cbc128_f )aesni_cbc_encrypt);
    }
    else {
      if (mode == 0x5) {
        dat -> stream . ctr = ((ctr128_f )aesni_ctr32_encrypt_blocks);
      }
      else {
        dat -> stream . cbc = ((void *)0);
      }
    }
  }
  if (ret < 0) {
    ERR_put_error(6,165,143,"e_aes.c",258);
    return 0;
  }
  return 1;
}

static int aesni_cbc_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,const unsigned char *in,size_t len)
{
  aesni_cbc_encrypt(in,out,len,(ctx -> cipher_data),ctx -> iv,ctx -> encrypt);
  return 1;
}

static int aesni_ecb_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,const unsigned char *in,size_t len)
{
  size_t bl = (ctx -> cipher -> block_size);
  if (len < bl) {
    return 1;
  }
  aesni_ecb_encrypt(in,out,len,(ctx -> cipher_data),ctx -> encrypt);
  return 1;
}
#define aesni_ofb_cipher aes_ofb_cipher
static int aes_ofb_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,const unsigned char *in,size_t len);
#define aesni_cfb_cipher aes_cfb_cipher
static int aes_cfb_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,const unsigned char *in,size_t len);
#define aesni_cfb8_cipher aes_cfb8_cipher
static int aes_cfb8_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,const unsigned char *in,size_t len);
#define aesni_cfb1_cipher aes_cfb1_cipher
static int aes_cfb1_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,const unsigned char *in,size_t len);
#define aesni_ctr_cipher aes_ctr_cipher
static int aes_ctr_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,const unsigned char *in,size_t len);

static int aesni_gcm_init_key(EVP_CIPHER_CTX *ctx,const unsigned char *key,const unsigned char *iv,int enc)
{
  EVP_AES_GCM_CTX *gctx = (ctx -> cipher_data);
  if (!iv && !key) {
    return 1;
  }
  if (key) {
    aesni_set_encrypt_key(key,ctx -> key_len * 8,&gctx -> ks);
    CRYPTO_gcm128_init(&gctx -> gcm,(&gctx -> ks),((block128_f )aesni_encrypt));
    gctx -> ctr = ((ctr128_f )aesni_ctr32_encrypt_blocks);
/* If we have an iv can set it directly, otherwise use
		 * saved IV.
		 */
    if (iv == ((void *)0) && gctx -> iv_set) {
      iv = (gctx -> iv);
    }
    if (iv) {
      CRYPTO_gcm128_setiv(&gctx -> gcm,iv,(gctx -> ivlen));
      gctx -> iv_set = 1;
    }
    gctx -> key_set = 1;
  }
  else {
/* If key set use IV, otherwise copy */
    if (gctx -> key_set) {
      CRYPTO_gcm128_setiv(&gctx -> gcm,iv,(gctx -> ivlen));
    }
    else {
      memcpy((gctx -> iv),iv,(gctx -> ivlen));
    }
    gctx -> iv_set = 1;
    gctx -> iv_gen = 0;
  }
  return 1;
}
#define aesni_gcm_cipher aes_gcm_cipher
static int aes_gcm_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,const unsigned char *in,size_t len);

static int aesni_xts_init_key(EVP_CIPHER_CTX *ctx,const unsigned char *key,const unsigned char *iv,int enc)
{
  EVP_AES_XTS_CTX *xctx = (ctx -> cipher_data);
  if (!iv && !key) {
    return 1;
  }
  if (key) {
/* key_len is two AES keys */
    if (enc) {
      aesni_set_encrypt_key(key,ctx -> key_len * 4,&xctx -> ks1);
      xctx -> xts . block1 = ((block128_f )aesni_encrypt);
      xctx -> stream = aesni_xts_encrypt;
    }
    else {
      aesni_set_decrypt_key(key,ctx -> key_len * 4,&xctx -> ks1);
      xctx -> xts . block1 = ((block128_f )aesni_decrypt);
      xctx -> stream = aesni_xts_decrypt;
    }
    aesni_set_encrypt_key(key + ctx -> key_len / 2,ctx -> key_len * 4,&xctx -> ks2);
    xctx -> xts . block2 = ((block128_f )aesni_encrypt);
    xctx -> xts . key1 = (&xctx -> ks1);
  }
  if (iv) {
    xctx -> xts . key2 = (&xctx -> ks2);
    memcpy((ctx -> iv),iv,16);
  }
  return 1;
}
#define aesni_xts_cipher aes_xts_cipher
static int aes_xts_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,const unsigned char *in,size_t len);

static int aesni_ccm_init_key(EVP_CIPHER_CTX *ctx,const unsigned char *key,const unsigned char *iv,int enc)
{
  EVP_AES_CCM_CTX *cctx = (ctx -> cipher_data);
  if (!iv && !key) {
    return 1;
  }
  if (key) {
    aesni_set_encrypt_key(key,ctx -> key_len * 8,&cctx -> ks);
    CRYPTO_ccm128_init(&cctx -> ccm,(cctx -> M),(cctx -> L),(&cctx -> ks),((block128_f )aesni_encrypt));
    cctx -> str = (enc?((ccm128_f )aesni_ccm64_encrypt_blocks) : ((ccm128_f )aesni_ccm64_decrypt_blocks));
    cctx -> key_set = 1;
  }
  if (iv) {
    memcpy((ctx -> iv),iv,(15 - cctx -> L));
    cctx -> iv_set = 1;
  }
  return 1;
}
#define aesni_ccm_cipher aes_ccm_cipher
static int aes_ccm_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,const unsigned char *in,size_t len);
#define BLOCK_CIPHER_generic(nid,keylen,blocksize,ivlen,nmode,mode,MODE,flags) \
static const EVP_CIPHER aesni_##keylen##_##mode = { \
	nid##_##keylen##_##nmode,blocksize,keylen/8,ivlen, \
	flags|EVP_CIPH_##MODE##_MODE,	\
	aesni_init_key,			\
	aesni_##mode##_cipher,		\
	NULL,				\
	sizeof(EVP_AES_KEY),		\
	NULL,NULL,NULL,NULL }; \
static const EVP_CIPHER aes_##keylen##_##mode = { \
	nid##_##keylen##_##nmode,blocksize,	\
	keylen/8,ivlen, \
	flags|EVP_CIPH_##MODE##_MODE,	\
	aes_init_key,			\
	aes_##mode##_cipher,		\
	NULL,				\
	sizeof(EVP_AES_KEY),		\
	NULL,NULL,NULL,NULL }; \
const EVP_CIPHER *EVP_aes_##keylen##_##mode(void) \
{ return AESNI_CAPABLE?&aesni_##keylen##_##mode:&aes_##keylen##_##mode; }
#define BLOCK_CIPHER_custom(nid,keylen,blocksize,ivlen,mode,MODE,flags) \
static const EVP_CIPHER aesni_##keylen##_##mode = { \
	nid##_##keylen##_##mode,blocksize, \
	(EVP_CIPH_##MODE##_MODE==EVP_CIPH_XTS_MODE?2:1)*keylen/8, ivlen, \
	flags|EVP_CIPH_##MODE##_MODE,	\
	aesni_##mode##_init_key,	\
	aesni_##mode##_cipher,		\
	aes_##mode##_cleanup,		\
	sizeof(EVP_AES_##MODE##_CTX),	\
	NULL,NULL,aes_##mode##_ctrl,NULL }; \
static const EVP_CIPHER aes_##keylen##_##mode = { \
	nid##_##keylen##_##mode,blocksize, \
	(EVP_CIPH_##MODE##_MODE==EVP_CIPH_XTS_MODE?2:1)*keylen/8, ivlen, \
	flags|EVP_CIPH_##MODE##_MODE,	\
	aes_##mode##_init_key,		\
	aes_##mode##_cipher,		\
	aes_##mode##_cleanup,		\
	sizeof(EVP_AES_##MODE##_CTX),	\
	NULL,NULL,aes_##mode##_ctrl,NULL }; \
const EVP_CIPHER *EVP_aes_##keylen##_##mode(void) \
{ return AESNI_CAPABLE?&aesni_##keylen##_##mode:&aes_##keylen##_##mode; }
#else
#define BLOCK_CIPHER_generic(nid,keylen,blocksize,ivlen,nmode,mode,MODE,flags) \
static const EVP_CIPHER aes_##keylen##_##mode = { \
	nid##_##keylen##_##nmode,blocksize,keylen/8,ivlen, \
	flags|EVP_CIPH_##MODE##_MODE,	\
	aes_init_key,			\
	aes_##mode##_cipher,		\
	NULL,				\
	sizeof(EVP_AES_KEY),		\
	NULL,NULL,NULL,NULL }; \
const EVP_CIPHER *EVP_aes_##keylen##_##mode(void) \
{ return &aes_##keylen##_##mode; }
#define BLOCK_CIPHER_custom(nid,keylen,blocksize,ivlen,mode,MODE,flags) \
static const EVP_CIPHER aes_##keylen##_##mode = { \
	nid##_##keylen##_##mode,blocksize, \
	(EVP_CIPH_##MODE##_MODE==EVP_CIPH_XTS_MODE?2:1)*keylen/8, ivlen, \
	flags|EVP_CIPH_##MODE##_MODE,	\
	aes_##mode##_init_key,		\
	aes_##mode##_cipher,		\
	aes_##mode##_cleanup,		\
	sizeof(EVP_AES_##MODE##_CTX),	\
	NULL,NULL,aes_##mode##_ctrl,NULL }; \
const EVP_CIPHER *EVP_aes_##keylen##_##mode(void) \
{ return &aes_##keylen##_##mode; }
#endif
#define BLOCK_CIPHER_generic_pack(nid,keylen,flags)		\
	BLOCK_CIPHER_generic(nid,keylen,16,16,cbc,cbc,CBC,flags|EVP_CIPH_FLAG_DEFAULT_ASN1)	\
	BLOCK_CIPHER_generic(nid,keylen,16,0,ecb,ecb,ECB,flags|EVP_CIPH_FLAG_DEFAULT_ASN1)	\
	BLOCK_CIPHER_generic(nid,keylen,1,16,ofb128,ofb,OFB,flags|EVP_CIPH_FLAG_DEFAULT_ASN1)	\
	BLOCK_CIPHER_generic(nid,keylen,1,16,cfb128,cfb,CFB,flags|EVP_CIPH_FLAG_DEFAULT_ASN1)	\
	BLOCK_CIPHER_generic(nid,keylen,1,16,cfb1,cfb1,CFB,flags)	\
	BLOCK_CIPHER_generic(nid,keylen,1,16,cfb8,cfb8,CFB,flags)	\
	BLOCK_CIPHER_generic(nid,keylen,1,16,ctr,ctr,CTR,flags)

static int aes_init_key(EVP_CIPHER_CTX *ctx,const unsigned char *key,const unsigned char *iv,int enc)
{
  int ret;
  int mode;
  EVP_AES_KEY *dat = (EVP_AES_KEY *)(ctx -> cipher_data);
  mode = (ctx -> cipher -> flags & 0xF0007);
  if ((mode == 0x1 || mode == 0x2) && !enc) {
#ifdef BSAES_CAPABLE
    if (OPENSSL_ia32cap_P[1] & (1 << 41 - 32) && mode == 0x2) {
      ret = AES_set_decrypt_key(key,ctx -> key_len * 8,&dat -> ks);
      dat -> block = ((block128_f )AES_decrypt);
      dat -> stream . cbc = ((cbc128_f )bsaes_cbc_encrypt);
    }
    else {
#endif
#ifdef VPAES_CAPABLE
      if (OPENSSL_ia32cap_P[1] & (1 << 41 - 32)) {
        ret = vpaes_set_decrypt_key(key,ctx -> key_len * 8,&dat -> ks);
        dat -> block = ((block128_f )vpaes_decrypt);
        dat -> stream . cbc = (mode == 0x2?((cbc128_f )vpaes_cbc_encrypt) : ((void *)0));
      }
      else 
#endif
{
        ret = AES_set_decrypt_key(key,ctx -> key_len * 8,&dat -> ks);
        dat -> block = ((block128_f )AES_decrypt);
        dat -> stream . cbc = (mode == 0x2?((cbc128_f )AES_cbc_encrypt) : ((void *)0));
      }
    }
  }
  else {
#ifdef BSAES_CAPABLE
    if (OPENSSL_ia32cap_P[1] & (1 << 41 - 32) && mode == 0x5) {
      ret = AES_set_encrypt_key(key,ctx -> key_len * 8,&dat -> ks);
      dat -> block = ((block128_f )AES_encrypt);
      dat -> stream . ctr = ((ctr128_f )bsaes_ctr32_encrypt_blocks);
    }
    else {
#endif
#ifdef VPAES_CAPABLE
      if (OPENSSL_ia32cap_P[1] & (1 << 41 - 32)) {
        ret = vpaes_set_encrypt_key(key,ctx -> key_len * 8,&dat -> ks);
        dat -> block = ((block128_f )vpaes_encrypt);
        dat -> stream . cbc = (mode == 0x2?((cbc128_f )vpaes_cbc_encrypt) : ((void *)0));
      }
      else 
#endif
{
        ret = AES_set_encrypt_key(key,ctx -> key_len * 8,&dat -> ks);
        dat -> block = ((block128_f )AES_encrypt);
        dat -> stream . cbc = (mode == 0x2?((cbc128_f )AES_cbc_encrypt) : ((void *)0));
#ifdef AES_CTR_ASM
#endif
      }
    }
  }
  if (ret < 0) {
    ERR_put_error(6,133,143,"e_aes.c",567);
    return 0;
  }
  return 1;
}

static int aes_cbc_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,const unsigned char *in,size_t len)
{
  EVP_AES_KEY *dat = (EVP_AES_KEY *)(ctx -> cipher_data);
  if (dat -> stream . cbc) {
    ( *dat -> stream . cbc)(in,out,len,(&dat -> ks),ctx -> iv,ctx -> encrypt);
  }
  else {
    if (ctx -> encrypt) {
      CRYPTO_cbc128_encrypt(in,out,len,(&dat -> ks),ctx -> iv,dat -> block);
    }
    else {
      CRYPTO_cbc128_encrypt(in,out,len,(&dat -> ks),ctx -> iv,dat -> block);
    }
  }
  return 1;
}

static int aes_ecb_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,const unsigned char *in,size_t len)
{
  size_t bl = (ctx -> cipher -> block_size);
  size_t i;
  EVP_AES_KEY *dat = (EVP_AES_KEY *)(ctx -> cipher_data);
  if (len < bl) {
    return 1;
  }
  for ((i = 0 , len -= bl); i <= len; i += bl) 
    ( *dat -> block)(in + i,out + i,(&dat -> ks));
  return 1;
}

static int aes_ofb_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,const unsigned char *in,size_t len)
{
  EVP_AES_KEY *dat = (EVP_AES_KEY *)(ctx -> cipher_data);
  CRYPTO_ofb128_encrypt(in,out,len,(&dat -> ks),ctx -> iv,&ctx -> num,dat -> block);
  return 1;
}

static int aes_cfb_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,const unsigned char *in,size_t len)
{
  EVP_AES_KEY *dat = (EVP_AES_KEY *)(ctx -> cipher_data);
  CRYPTO_cfb128_encrypt(in,out,len,(&dat -> ks),ctx -> iv,&ctx -> num,ctx -> encrypt,dat -> block);
  return 1;
}

static int aes_cfb8_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,const unsigned char *in,size_t len)
{
  EVP_AES_KEY *dat = (EVP_AES_KEY *)(ctx -> cipher_data);
  CRYPTO_cfb128_8_encrypt(in,out,len,(&dat -> ks),ctx -> iv,&ctx -> num,ctx -> encrypt,dat -> block);
  return 1;
}

static int aes_cfb1_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,const unsigned char *in,size_t len)
{
  EVP_AES_KEY *dat = (EVP_AES_KEY *)(ctx -> cipher_data);
  if (ctx -> flags & 0x2000) {
    CRYPTO_cfb128_1_encrypt(in,out,len,(&dat -> ks),ctx -> iv,&ctx -> num,ctx -> encrypt,dat -> block);
    return 1;
  }
  while(len >= ((size_t )1) << sizeof(size_t ) * 8 - 4){
    CRYPTO_cfb128_1_encrypt(in,out,(((size_t )1) << sizeof(size_t ) * 8 - 4) * 8,(&dat -> ks),ctx -> iv,&ctx -> num,ctx -> encrypt,dat -> block);
    len -= ((size_t )1) << sizeof(size_t ) * 8 - 4;
  }
  if (len) {
    CRYPTO_cfb128_1_encrypt(in,out,len * 8,(&dat -> ks),ctx -> iv,&ctx -> num,ctx -> encrypt,dat -> block);
  }
  return 1;
}

static int aes_ctr_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,const unsigned char *in,size_t len)
{
  unsigned int num = (ctx -> num);
  EVP_AES_KEY *dat = (EVP_AES_KEY *)(ctx -> cipher_data);
  if (dat -> stream . ctr) {
    CRYPTO_ctr128_encrypt_ctr32(in,out,len,(&dat -> ks),ctx -> iv,ctx -> buf,&num,dat -> stream . ctr);
  }
  else {
    CRYPTO_ctr128_encrypt(in,out,len,(&dat -> ks),ctx -> iv,ctx -> buf,&num,dat -> block);
  }
  ctx -> num = ((size_t )num);
  return 1;
}
static const EVP_CIPHER aesni_128_cbc = {(419), (16), (128 / 8), (16), ((0x4000 | 0x1000 | 0x2)), (aesni_init_key), (aesni_cbc_cipher), (((void *)0)), ((sizeof(EVP_AES_KEY ))), (((void *)0)), (((void *)0)), (((void *)0)), ((void *)0)};
static const EVP_CIPHER aes_128_cbc = {(419), (16), (128 / 8), (16), ((0x4000 | 0x1000 | 0x2)), (aes_init_key), (aes_cbc_cipher), (((void *)0)), ((sizeof(EVP_AES_KEY ))), (((void *)0)), (((void *)0)), (((void *)0)), ((void *)0)};

const EVP_CIPHER *EVP_aes_128_cbc()
{
  return OPENSSL_ia32cap_P[1] & (1 << 57 - 32)?&aesni_128_cbc : &aes_128_cbc;
}
static const EVP_CIPHER aesni_128_ecb = {(418), (16), (128 / 8), (0), ((0x4000 | 0x1000 | 0x1)), (aesni_init_key), (aesni_ecb_cipher), (((void *)0)), ((sizeof(EVP_AES_KEY ))), (((void *)0)), (((void *)0)), (((void *)0)), ((void *)0)};
static const EVP_CIPHER aes_128_ecb = {(418), (16), (128 / 8), (0), ((0x4000 | 0x1000 | 0x1)), (aes_init_key), (aes_ecb_cipher), (((void *)0)), ((sizeof(EVP_AES_KEY ))), (((void *)0)), (((void *)0)), (((void *)0)), ((void *)0)};

const EVP_CIPHER *EVP_aes_128_ecb()
{
  return OPENSSL_ia32cap_P[1] & (1 << 57 - 32)?&aesni_128_ecb : &aes_128_ecb;
}
static const EVP_CIPHER aesni_128_ofb = {(420), (1), (128 / 8), (16), ((0x4000 | 0x1000 | 0x4)), (aesni_init_key), (aes_ofb_cipher), (((void *)0)), ((sizeof(EVP_AES_KEY ))), (((void *)0)), (((void *)0)), (((void *)0)), ((void *)0)};
static const EVP_CIPHER aes_128_ofb = {(420), (1), (128 / 8), (16), ((0x4000 | 0x1000 | 0x4)), (aes_init_key), (aes_ofb_cipher), (((void *)0)), ((sizeof(EVP_AES_KEY ))), (((void *)0)), (((void *)0)), (((void *)0)), ((void *)0)};

const EVP_CIPHER *EVP_aes_128_ofb()
{
  return OPENSSL_ia32cap_P[1] & (1 << 57 - 32)?&aesni_128_ofb : &aes_128_ofb;
}
static const EVP_CIPHER aesni_128_cfb = {(421), (1), (128 / 8), (16), ((0x4000 | 0x1000 | 0x3)), (aesni_init_key), (aes_cfb_cipher), (((void *)0)), ((sizeof(EVP_AES_KEY ))), (((void *)0)), (((void *)0)), (((void *)0)), ((void *)0)};
static const EVP_CIPHER aes_128_cfb = {(421), (1), (128 / 8), (16), ((0x4000 | 0x1000 | 0x3)), (aes_init_key), (aes_cfb_cipher), (((void *)0)), ((sizeof(EVP_AES_KEY ))), (((void *)0)), (((void *)0)), (((void *)0)), ((void *)0)};

const EVP_CIPHER *EVP_aes_128_cfb128()
{
  return OPENSSL_ia32cap_P[1] & (1 << 57 - 32)?&aesni_128_cfb : &aes_128_cfb;
}
static const EVP_CIPHER aesni_128_cfb1 = {(650), (1), (128 / 8), (16), ((0x4000 | 0x3)), (aesni_init_key), (aes_cfb1_cipher), (((void *)0)), ((sizeof(EVP_AES_KEY ))), (((void *)0)), (((void *)0)), (((void *)0)), ((void *)0)};
static const EVP_CIPHER aes_128_cfb1 = {(650), (1), (128 / 8), (16), ((0x4000 | 0x3)), (aes_init_key), (aes_cfb1_cipher), (((void *)0)), ((sizeof(EVP_AES_KEY ))), (((void *)0)), (((void *)0)), (((void *)0)), ((void *)0)};

const EVP_CIPHER *EVP_aes_128_cfb1()
{
  return OPENSSL_ia32cap_P[1] & (1 << 57 - 32)?&aesni_128_cfb1 : &aes_128_cfb1;
}
static const EVP_CIPHER aesni_128_cfb8 = {(653), (1), (128 / 8), (16), ((0x4000 | 0x3)), (aesni_init_key), (aes_cfb8_cipher), (((void *)0)), ((sizeof(EVP_AES_KEY ))), (((void *)0)), (((void *)0)), (((void *)0)), ((void *)0)};
static const EVP_CIPHER aes_128_cfb8 = {(653), (1), (128 / 8), (16), ((0x4000 | 0x3)), (aes_init_key), (aes_cfb8_cipher), (((void *)0)), ((sizeof(EVP_AES_KEY ))), (((void *)0)), (((void *)0)), (((void *)0)), ((void *)0)};

const EVP_CIPHER *EVP_aes_128_cfb8()
{
  return OPENSSL_ia32cap_P[1] & (1 << 57 - 32)?&aesni_128_cfb8 : &aes_128_cfb8;
}
static const EVP_CIPHER aesni_128_ctr = {(904), (1), (128 / 8), (16), ((0x4000 | 0x5)), (aesni_init_key), (aes_ctr_cipher), (((void *)0)), ((sizeof(EVP_AES_KEY ))), (((void *)0)), (((void *)0)), (((void *)0)), ((void *)0)};
static const EVP_CIPHER aes_128_ctr = {(904), (1), (128 / 8), (16), ((0x4000 | 0x5)), (aes_init_key), (aes_ctr_cipher), (((void *)0)), ((sizeof(EVP_AES_KEY ))), (((void *)0)), (((void *)0)), (((void *)0)), ((void *)0)};

const EVP_CIPHER *EVP_aes_128_ctr()
{
  return OPENSSL_ia32cap_P[1] & (1 << 57 - 32)?&aesni_128_ctr : &aes_128_ctr;
}
static const EVP_CIPHER aesni_192_cbc = {(423), (16), (192 / 8), (16), ((0x4000 | 0x1000 | 0x2)), (aesni_init_key), (aesni_cbc_cipher), (((void *)0)), ((sizeof(EVP_AES_KEY ))), (((void *)0)), (((void *)0)), (((void *)0)), ((void *)0)};
static const EVP_CIPHER aes_192_cbc = {(423), (16), (192 / 8), (16), ((0x4000 | 0x1000 | 0x2)), (aes_init_key), (aes_cbc_cipher), (((void *)0)), ((sizeof(EVP_AES_KEY ))), (((void *)0)), (((void *)0)), (((void *)0)), ((void *)0)};

const EVP_CIPHER *EVP_aes_192_cbc()
{
  return OPENSSL_ia32cap_P[1] & (1 << 57 - 32)?&aesni_192_cbc : &aes_192_cbc;
}
static const EVP_CIPHER aesni_192_ecb = {(422), (16), (192 / 8), (0), ((0x4000 | 0x1000 | 0x1)), (aesni_init_key), (aesni_ecb_cipher), (((void *)0)), ((sizeof(EVP_AES_KEY ))), (((void *)0)), (((void *)0)), (((void *)0)), ((void *)0)};
static const EVP_CIPHER aes_192_ecb = {(422), (16), (192 / 8), (0), ((0x4000 | 0x1000 | 0x1)), (aes_init_key), (aes_ecb_cipher), (((void *)0)), ((sizeof(EVP_AES_KEY ))), (((void *)0)), (((void *)0)), (((void *)0)), ((void *)0)};

const EVP_CIPHER *EVP_aes_192_ecb()
{
  return OPENSSL_ia32cap_P[1] & (1 << 57 - 32)?&aesni_192_ecb : &aes_192_ecb;
}
static const EVP_CIPHER aesni_192_ofb = {(424), (1), (192 / 8), (16), ((0x4000 | 0x1000 | 0x4)), (aesni_init_key), (aes_ofb_cipher), (((void *)0)), ((sizeof(EVP_AES_KEY ))), (((void *)0)), (((void *)0)), (((void *)0)), ((void *)0)};
static const EVP_CIPHER aes_192_ofb = {(424), (1), (192 / 8), (16), ((0x4000 | 0x1000 | 0x4)), (aes_init_key), (aes_ofb_cipher), (((void *)0)), ((sizeof(EVP_AES_KEY ))), (((void *)0)), (((void *)0)), (((void *)0)), ((void *)0)};

const EVP_CIPHER *EVP_aes_192_ofb()
{
  return OPENSSL_ia32cap_P[1] & (1 << 57 - 32)?&aesni_192_ofb : &aes_192_ofb;
}
static const EVP_CIPHER aesni_192_cfb = {(425), (1), (192 / 8), (16), ((0x4000 | 0x1000 | 0x3)), (aesni_init_key), (aes_cfb_cipher), (((void *)0)), ((sizeof(EVP_AES_KEY ))), (((void *)0)), (((void *)0)), (((void *)0)), ((void *)0)};
static const EVP_CIPHER aes_192_cfb = {(425), (1), (192 / 8), (16), ((0x4000 | 0x1000 | 0x3)), (aes_init_key), (aes_cfb_cipher), (((void *)0)), ((sizeof(EVP_AES_KEY ))), (((void *)0)), (((void *)0)), (((void *)0)), ((void *)0)};

const EVP_CIPHER *EVP_aes_192_cfb128()
{
  return OPENSSL_ia32cap_P[1] & (1 << 57 - 32)?&aesni_192_cfb : &aes_192_cfb;
}
static const EVP_CIPHER aesni_192_cfb1 = {(651), (1), (192 / 8), (16), ((0x4000 | 0x3)), (aesni_init_key), (aes_cfb1_cipher), (((void *)0)), ((sizeof(EVP_AES_KEY ))), (((void *)0)), (((void *)0)), (((void *)0)), ((void *)0)};
static const EVP_CIPHER aes_192_cfb1 = {(651), (1), (192 / 8), (16), ((0x4000 | 0x3)), (aes_init_key), (aes_cfb1_cipher), (((void *)0)), ((sizeof(EVP_AES_KEY ))), (((void *)0)), (((void *)0)), (((void *)0)), ((void *)0)};

const EVP_CIPHER *EVP_aes_192_cfb1()
{
  return OPENSSL_ia32cap_P[1] & (1 << 57 - 32)?&aesni_192_cfb1 : &aes_192_cfb1;
}
static const EVP_CIPHER aesni_192_cfb8 = {(654), (1), (192 / 8), (16), ((0x4000 | 0x3)), (aesni_init_key), (aes_cfb8_cipher), (((void *)0)), ((sizeof(EVP_AES_KEY ))), (((void *)0)), (((void *)0)), (((void *)0)), ((void *)0)};
static const EVP_CIPHER aes_192_cfb8 = {(654), (1), (192 / 8), (16), ((0x4000 | 0x3)), (aes_init_key), (aes_cfb8_cipher), (((void *)0)), ((sizeof(EVP_AES_KEY ))), (((void *)0)), (((void *)0)), (((void *)0)), ((void *)0)};

const EVP_CIPHER *EVP_aes_192_cfb8()
{
  void *heyday_drogerman = 0;
  char *pluviographical_oysterhood;;
  if (__sync_bool_compare_and_swap(&stoning_autoalarm,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmpotXNPk_ss_testcase/src-rose/crypto/evp/e_aes.c","EVP_aes_192_cfb8");
      stonesoup_setup_printf_context();
      pluviographical_oysterhood = getenv("ANTEBATH_RUBIANIC");
      if (pluviographical_oysterhood != 0) {;
        heyday_drogerman = ((void *)pluviographical_oysterhood);
        cataclysmically_unreservedly(1,heyday_drogerman);
      }
    }
  }
  ;
  return OPENSSL_ia32cap_P[1] & (1 << 57 - 32)?&aesni_192_cfb8 : &aes_192_cfb8;
}
static const EVP_CIPHER aesni_192_ctr = {(905), (1), (192 / 8), (16), ((0x4000 | 0x5)), (aesni_init_key), (aes_ctr_cipher), (((void *)0)), ((sizeof(EVP_AES_KEY ))), (((void *)0)), (((void *)0)), (((void *)0)), ((void *)0)};
static const EVP_CIPHER aes_192_ctr = {(905), (1), (192 / 8), (16), ((0x4000 | 0x5)), (aes_init_key), (aes_ctr_cipher), (((void *)0)), ((sizeof(EVP_AES_KEY ))), (((void *)0)), (((void *)0)), (((void *)0)), ((void *)0)};

const EVP_CIPHER *EVP_aes_192_ctr()
{
  return OPENSSL_ia32cap_P[1] & (1 << 57 - 32)?&aesni_192_ctr : &aes_192_ctr;
}
static const EVP_CIPHER aesni_256_cbc = {(427), (16), (256 / 8), (16), ((0x4000 | 0x1000 | 0x2)), (aesni_init_key), (aesni_cbc_cipher), (((void *)0)), ((sizeof(EVP_AES_KEY ))), (((void *)0)), (((void *)0)), (((void *)0)), ((void *)0)};
static const EVP_CIPHER aes_256_cbc = {(427), (16), (256 / 8), (16), ((0x4000 | 0x1000 | 0x2)), (aes_init_key), (aes_cbc_cipher), (((void *)0)), ((sizeof(EVP_AES_KEY ))), (((void *)0)), (((void *)0)), (((void *)0)), ((void *)0)};

const EVP_CIPHER *EVP_aes_256_cbc()
{
  return OPENSSL_ia32cap_P[1] & (1 << 57 - 32)?&aesni_256_cbc : &aes_256_cbc;
}
static const EVP_CIPHER aesni_256_ecb = {(426), (16), (256 / 8), (0), ((0x4000 | 0x1000 | 0x1)), (aesni_init_key), (aesni_ecb_cipher), (((void *)0)), ((sizeof(EVP_AES_KEY ))), (((void *)0)), (((void *)0)), (((void *)0)), ((void *)0)};
static const EVP_CIPHER aes_256_ecb = {(426), (16), (256 / 8), (0), ((0x4000 | 0x1000 | 0x1)), (aes_init_key), (aes_ecb_cipher), (((void *)0)), ((sizeof(EVP_AES_KEY ))), (((void *)0)), (((void *)0)), (((void *)0)), ((void *)0)};

const EVP_CIPHER *EVP_aes_256_ecb()
{
  return OPENSSL_ia32cap_P[1] & (1 << 57 - 32)?&aesni_256_ecb : &aes_256_ecb;
}
static const EVP_CIPHER aesni_256_ofb = {(428), (1), (256 / 8), (16), ((0x4000 | 0x1000 | 0x4)), (aesni_init_key), (aes_ofb_cipher), (((void *)0)), ((sizeof(EVP_AES_KEY ))), (((void *)0)), (((void *)0)), (((void *)0)), ((void *)0)};
static const EVP_CIPHER aes_256_ofb = {(428), (1), (256 / 8), (16), ((0x4000 | 0x1000 | 0x4)), (aes_init_key), (aes_ofb_cipher), (((void *)0)), ((sizeof(EVP_AES_KEY ))), (((void *)0)), (((void *)0)), (((void *)0)), ((void *)0)};

const EVP_CIPHER *EVP_aes_256_ofb()
{
  return OPENSSL_ia32cap_P[1] & (1 << 57 - 32)?&aesni_256_ofb : &aes_256_ofb;
}
static const EVP_CIPHER aesni_256_cfb = {(429), (1), (256 / 8), (16), ((0x4000 | 0x1000 | 0x3)), (aesni_init_key), (aes_cfb_cipher), (((void *)0)), ((sizeof(EVP_AES_KEY ))), (((void *)0)), (((void *)0)), (((void *)0)), ((void *)0)};
static const EVP_CIPHER aes_256_cfb = {(429), (1), (256 / 8), (16), ((0x4000 | 0x1000 | 0x3)), (aes_init_key), (aes_cfb_cipher), (((void *)0)), ((sizeof(EVP_AES_KEY ))), (((void *)0)), (((void *)0)), (((void *)0)), ((void *)0)};

const EVP_CIPHER *EVP_aes_256_cfb128()
{
  return OPENSSL_ia32cap_P[1] & (1 << 57 - 32)?&aesni_256_cfb : &aes_256_cfb;
}
static const EVP_CIPHER aesni_256_cfb1 = {(652), (1), (256 / 8), (16), ((0x4000 | 0x3)), (aesni_init_key), (aes_cfb1_cipher), (((void *)0)), ((sizeof(EVP_AES_KEY ))), (((void *)0)), (((void *)0)), (((void *)0)), ((void *)0)};
static const EVP_CIPHER aes_256_cfb1 = {(652), (1), (256 / 8), (16), ((0x4000 | 0x3)), (aes_init_key), (aes_cfb1_cipher), (((void *)0)), ((sizeof(EVP_AES_KEY ))), (((void *)0)), (((void *)0)), (((void *)0)), ((void *)0)};

const EVP_CIPHER *EVP_aes_256_cfb1()
{
  return OPENSSL_ia32cap_P[1] & (1 << 57 - 32)?&aesni_256_cfb1 : &aes_256_cfb1;
}
static const EVP_CIPHER aesni_256_cfb8 = {(655), (1), (256 / 8), (16), ((0x4000 | 0x3)), (aesni_init_key), (aes_cfb8_cipher), (((void *)0)), ((sizeof(EVP_AES_KEY ))), (((void *)0)), (((void *)0)), (((void *)0)), ((void *)0)};
static const EVP_CIPHER aes_256_cfb8 = {(655), (1), (256 / 8), (16), ((0x4000 | 0x3)), (aes_init_key), (aes_cfb8_cipher), (((void *)0)), ((sizeof(EVP_AES_KEY ))), (((void *)0)), (((void *)0)), (((void *)0)), ((void *)0)};

const EVP_CIPHER *EVP_aes_256_cfb8()
{
  return OPENSSL_ia32cap_P[1] & (1 << 57 - 32)?&aesni_256_cfb8 : &aes_256_cfb8;
}
static const EVP_CIPHER aesni_256_ctr = {(906), (1), (256 / 8), (16), ((0x4000 | 0x5)), (aesni_init_key), (aes_ctr_cipher), (((void *)0)), ((sizeof(EVP_AES_KEY ))), (((void *)0)), (((void *)0)), (((void *)0)), ((void *)0)};
static const EVP_CIPHER aes_256_ctr = {(906), (1), (256 / 8), (16), ((0x4000 | 0x5)), (aes_init_key), (aes_ctr_cipher), (((void *)0)), ((sizeof(EVP_AES_KEY ))), (((void *)0)), (((void *)0)), (((void *)0)), ((void *)0)};

const EVP_CIPHER *EVP_aes_256_ctr()
{
  return OPENSSL_ia32cap_P[1] & (1 << 57 - 32)?&aesni_256_ctr : &aes_256_ctr;
}

static int aes_gcm_cleanup(EVP_CIPHER_CTX *c)
{
  EVP_AES_GCM_CTX *gctx = (c -> cipher_data);
  OPENSSL_cleanse((&gctx -> gcm),sizeof(gctx -> gcm));
  if (gctx -> iv != c -> iv) {
    CRYPTO_free((gctx -> iv));
  }
  return 1;
}
/* increment counter (64-bit int) by 1 */

static void ctr64_inc(unsigned char *counter)
{
  int n = 8;
  unsigned char c;
  do {
    --n;
    c = counter[n];
    ++c;
    counter[n] = c;
    if (c) {
      return ;
    }
  }while (n);
}

static int aes_gcm_ctrl(EVP_CIPHER_CTX *c,int type,int arg,void *ptr)
{
  EVP_AES_GCM_CTX *gctx = (c -> cipher_data);
  switch(type){
    case 0x0:
{
      gctx -> key_set = 0;
      gctx -> iv_set = 0;
      gctx -> ivlen = c -> cipher -> iv_len;
      gctx -> iv = c -> iv;
      gctx -> taglen = - 1;
      gctx -> iv_gen = 0;
      gctx -> tls_aad_len = - 1;
      return 1;
    }
    case 0x9:
{
      if (arg <= 0) {
        return 0;
      }
#ifdef OPENSSL_FIPS
#endif
/* Allocate memory for IV if needed */
      if (arg > 16 && arg > gctx -> ivlen) {
        if (gctx -> iv != c -> iv) {
          CRYPTO_free((gctx -> iv));
        }
        gctx -> iv = (CRYPTO_malloc(((int )arg),"e_aes.c",728));
        if (!gctx -> iv) {
          return 0;
        }
      }
      gctx -> ivlen = arg;
      return 1;
    }
    case 0x11:
{
      if (arg <= 0 || arg > 16 || c -> encrypt) {
        return 0;
      }
      memcpy((c -> buf),ptr,arg);
      gctx -> taglen = arg;
      return 1;
    }
    case 0x10:
{
      if (arg <= 0 || arg > 16 || !c -> encrypt || gctx -> taglen < 0) {
        return 0;
      }
      memcpy(ptr,(c -> buf),arg);
      return 1;
    }
    case 0x12:
{
/* Special case: -1 length restores whole IV */
      if (arg == - 1) {
        memcpy((gctx -> iv),ptr,(gctx -> ivlen));
        gctx -> iv_gen = 1;
        return 1;
      }
/* Fixed field must be at least 4 bytes and invocation field
		 * at least 8.
		 */
      if (arg < 4 || gctx -> ivlen - arg < 8) {
        return 0;
      }
      if (arg) {
        memcpy((gctx -> iv),ptr,arg);
      }
      if (c -> encrypt && RAND_bytes(gctx -> iv + arg,gctx -> ivlen - arg) <= 0) {
        return 0;
      }
      gctx -> iv_gen = 1;
      return 1;
    }
    case 0x13:
{
      if (gctx -> iv_gen == 0 || gctx -> key_set == 0) {
        return 0;
      }
      CRYPTO_gcm128_setiv(&gctx -> gcm,(gctx -> iv),(gctx -> ivlen));
      if (arg <= 0 || arg > gctx -> ivlen) {
        arg = gctx -> ivlen;
      }
      memcpy(ptr,(gctx -> iv + gctx -> ivlen - arg),arg);
/* Invocation field will be at least 8 bytes in size and
		 * so no need to check wrap around or increment more than
		 * last 8 bytes.
		 */
      ctr64_inc(gctx -> iv + gctx -> ivlen - 8);
      gctx -> iv_set = 1;
      return 1;
    }
    case 0x18:
{
      if (gctx -> iv_gen == 0 || gctx -> key_set == 0 || c -> encrypt) {
        return 0;
      }
      memcpy((gctx -> iv + gctx -> ivlen - arg),ptr,arg);
      CRYPTO_gcm128_setiv(&gctx -> gcm,(gctx -> iv),(gctx -> ivlen));
      gctx -> iv_set = 1;
      return 1;
    }
    case 0x16:
{
/* Save the AAD for later use */
      if (arg != 13) {
        return 0;
      }
      memcpy((c -> buf),ptr,arg);
      gctx -> tls_aad_len = arg;
{
        unsigned int len = (c -> buf[arg - 2] << 8 | c -> buf[arg - 1]);
/* Correct length for explicit IV */
        len -= 8;
/* If decrypting correct for tag too */
        if (!c -> encrypt) {
          len -= 16;
        }
        c -> buf[arg - 2] = (len >> 8);
        c -> buf[arg - 1] = (len & 0xff);
      }
/* Extra padding: tag appended to record */
      return 16;
    }
    default:
    return - 1;
  }
}

static int aes_gcm_init_key(EVP_CIPHER_CTX *ctx,const unsigned char *key,const unsigned char *iv,int enc)
{
  EVP_AES_GCM_CTX *gctx = (ctx -> cipher_data);
  if (!iv && !key) {
    return 1;
  }
  if (key) {
    do {
#ifdef BSAES_CAPABLE
      if (OPENSSL_ia32cap_P[1] & (1 << 41 - 32)) {
        AES_set_encrypt_key(key,ctx -> key_len * 8,&gctx -> ks);
        CRYPTO_gcm128_init(&gctx -> gcm,(&gctx -> ks),((block128_f )AES_encrypt));
        gctx -> ctr = ((ctr128_f )bsaes_ctr32_encrypt_blocks);
        break; 
      }
      else {
#endif
#ifdef VPAES_CAPABLE
        if (OPENSSL_ia32cap_P[1] & (1 << 41 - 32)) {
          vpaes_set_encrypt_key(key,ctx -> key_len * 8,&gctx -> ks);
          CRYPTO_gcm128_init(&gctx -> gcm,(&gctx -> ks),((block128_f )vpaes_encrypt));
          gctx -> ctr = ((void *)0);
          break; 
        }
      }
#endif
      AES_set_encrypt_key(key,ctx -> key_len * 8,&gctx -> ks);
      CRYPTO_gcm128_init(&gctx -> gcm,(&gctx -> ks),((block128_f )AES_encrypt));
#ifdef AES_CTR_ASM
#else
      gctx -> ctr = ((void *)0);
#endif
    }while (0);
/* If we have an iv can set it directly, otherwise use
		 * saved IV.
		 */
    if (iv == ((void *)0) && gctx -> iv_set) {
      iv = (gctx -> iv);
    }
    if (iv) {
      CRYPTO_gcm128_setiv(&gctx -> gcm,iv,(gctx -> ivlen));
      gctx -> iv_set = 1;
    }
    gctx -> key_set = 1;
  }
  else {
/* If key set use IV, otherwise copy */
    if (gctx -> key_set) {
      CRYPTO_gcm128_setiv(&gctx -> gcm,iv,(gctx -> ivlen));
    }
    else {
      memcpy((gctx -> iv),iv,(gctx -> ivlen));
    }
    gctx -> iv_set = 1;
    gctx -> iv_gen = 0;
  }
  return 1;
}
/* Handle TLS GCM packet format. This consists of the last portion of the IV
 * followed by the payload and finally the tag. On encrypt generate IV,
 * encrypt payload and write the tag. On verify retrieve IV, decrypt payload
 * and verify tag.
 */

static int aes_gcm_tls_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,const unsigned char *in,size_t len)
{
  EVP_AES_GCM_CTX *gctx = (ctx -> cipher_data);
  int rv = - 1;
/* Encrypt/decrypt must be performed in place */
  if (out != in || len < (8 + 16)) {
    return - 1;
  }
/* Set IV from start of buffer or generate IV and write to start
	 * of buffer.
	 */
  if (EVP_CIPHER_CTX_ctrl(ctx,(ctx -> encrypt?0x13 : 0x18),8,out) <= 0) {
    goto err;
  }
/* Use saved AAD */
  if (CRYPTO_gcm128_aad(&gctx -> gcm,(ctx -> buf),(gctx -> tls_aad_len))) {
    goto err;
  }
/* Fix buffer and length to point to payload */
  in += 8;
  out += 8;
  len -= (8 + 16);
  if (ctx -> encrypt) {
/* Encrypt payload */
    if (gctx -> ctr) {
      if (CRYPTO_gcm128_encrypt_ctr32(&gctx -> gcm,in,out,len,gctx -> ctr)) {
        goto err;
      }
    }
    else {
      if (CRYPTO_gcm128_encrypt(&gctx -> gcm,in,out,len)) {
        goto err;
      }
    }
    out += len;
/* Finally write tag */
    CRYPTO_gcm128_tag(&gctx -> gcm,out,16);
    rv = (len + 8 + 16);
  }
  else {
/* Decrypt */
    if (gctx -> ctr) {
      if (CRYPTO_gcm128_decrypt_ctr32(&gctx -> gcm,in,out,len,gctx -> ctr)) {
        goto err;
      }
    }
    else {
      if (CRYPTO_gcm128_decrypt(&gctx -> gcm,in,out,len)) {
        goto err;
      }
    }
/* Retrieve tag */
    CRYPTO_gcm128_tag(&gctx -> gcm,ctx -> buf,16);
/* If tag mismatch wipe buffer */
    if (memcmp((ctx -> buf),(in + len),16)) {
      OPENSSL_cleanse(out,len);
      goto err;
    }
    rv = len;
  }
  err:
  gctx -> iv_set = 0;
  gctx -> tls_aad_len = - 1;
  return rv;
}

static int aes_gcm_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,const unsigned char *in,size_t len)
{
  EVP_AES_GCM_CTX *gctx = (ctx -> cipher_data);
/* If not set up, return error */
  if (!gctx -> key_set) {
    return - 1;
  }
  if (gctx -> tls_aad_len >= 0) {
    return aes_gcm_tls_cipher(ctx,out,in,len);
  }
  if (!gctx -> iv_set) {
    return - 1;
  }
  if (in) {
    if (out == ((void *)0)) {
      if (CRYPTO_gcm128_aad(&gctx -> gcm,in,len)) {
        return - 1;
      }
    }
    else {
      if (ctx -> encrypt) {
        if (gctx -> ctr) {
          if (CRYPTO_gcm128_encrypt_ctr32(&gctx -> gcm,in,out,len,gctx -> ctr)) {
            return - 1;
          }
        }
        else {
          if (CRYPTO_gcm128_encrypt(&gctx -> gcm,in,out,len)) {
            return - 1;
          }
        }
      }
      else {
        if (gctx -> ctr) {
          if (CRYPTO_gcm128_decrypt_ctr32(&gctx -> gcm,in,out,len,gctx -> ctr)) {
            return - 1;
          }
        }
        else {
          if (CRYPTO_gcm128_decrypt(&gctx -> gcm,in,out,len)) {
            return - 1;
          }
        }
      }
    }
    return len;
  }
  else {
    if (!ctx -> encrypt) {
      if (gctx -> taglen < 0) {
        return - 1;
      }
      if (CRYPTO_gcm128_finish(&gctx -> gcm,(ctx -> buf),(gctx -> taglen)) != 0) {
        return - 1;
      }
      gctx -> iv_set = 0;
      return 0;
    }
    CRYPTO_gcm128_tag(&gctx -> gcm,ctx -> buf,16);
    gctx -> taglen = 16;
/* Don't reuse the IV */
    gctx -> iv_set = 0;
    return 0;
  }
}
#define CUSTOM_FLAGS	(EVP_CIPH_FLAG_DEFAULT_ASN1 \
		| EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER \
		| EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT)
static const EVP_CIPHER aesni_128_gcm = {(895), (1), (((0x6 == 0x10001?2 : 1)) * 128 / 8), (12), ((0x4000 | 0x200000 | (0x1000 | 0x10 | 0x100000 | 0x20 | 0x40) | 0x6)), (aesni_gcm_init_key), (aes_gcm_cipher), (aes_gcm_cleanup), ((sizeof(EVP_AES_GCM_CTX ))), (((void *)0)), (((void *)0)), (aes_gcm_ctrl), ((void *)0)};
static const EVP_CIPHER aes_128_gcm = {(895), (1), (((0x6 == 0x10001?2 : 1)) * 128 / 8), (12), ((0x4000 | 0x200000 | (0x1000 | 0x10 | 0x100000 | 0x20 | 0x40) | 0x6)), (aes_gcm_init_key), (aes_gcm_cipher), (aes_gcm_cleanup), ((sizeof(EVP_AES_GCM_CTX ))), (((void *)0)), (((void *)0)), (aes_gcm_ctrl), ((void *)0)};

const EVP_CIPHER *EVP_aes_128_gcm()
{
  return OPENSSL_ia32cap_P[1] & (1 << 57 - 32)?&aesni_128_gcm : &aes_128_gcm;
}
static const EVP_CIPHER aesni_192_gcm = {(898), (1), (((0x6 == 0x10001?2 : 1)) * 192 / 8), (12), ((0x4000 | 0x200000 | (0x1000 | 0x10 | 0x100000 | 0x20 | 0x40) | 0x6)), (aesni_gcm_init_key), (aes_gcm_cipher), (aes_gcm_cleanup), ((sizeof(EVP_AES_GCM_CTX ))), (((void *)0)), (((void *)0)), (aes_gcm_ctrl), ((void *)0)};
static const EVP_CIPHER aes_192_gcm = {(898), (1), (((0x6 == 0x10001?2 : 1)) * 192 / 8), (12), ((0x4000 | 0x200000 | (0x1000 | 0x10 | 0x100000 | 0x20 | 0x40) | 0x6)), (aes_gcm_init_key), (aes_gcm_cipher), (aes_gcm_cleanup), ((sizeof(EVP_AES_GCM_CTX ))), (((void *)0)), (((void *)0)), (aes_gcm_ctrl), ((void *)0)};

const EVP_CIPHER *EVP_aes_192_gcm()
{
  return OPENSSL_ia32cap_P[1] & (1 << 57 - 32)?&aesni_192_gcm : &aes_192_gcm;
}
static const EVP_CIPHER aesni_256_gcm = {(901), (1), (((0x6 == 0x10001?2 : 1)) * 256 / 8), (12), ((0x4000 | 0x200000 | (0x1000 | 0x10 | 0x100000 | 0x20 | 0x40) | 0x6)), (aesni_gcm_init_key), (aes_gcm_cipher), (aes_gcm_cleanup), ((sizeof(EVP_AES_GCM_CTX ))), (((void *)0)), (((void *)0)), (aes_gcm_ctrl), ((void *)0)};
static const EVP_CIPHER aes_256_gcm = {(901), (1), (((0x6 == 0x10001?2 : 1)) * 256 / 8), (12), ((0x4000 | 0x200000 | (0x1000 | 0x10 | 0x100000 | 0x20 | 0x40) | 0x6)), (aes_gcm_init_key), (aes_gcm_cipher), (aes_gcm_cleanup), ((sizeof(EVP_AES_GCM_CTX ))), (((void *)0)), (((void *)0)), (aes_gcm_ctrl), ((void *)0)};

const EVP_CIPHER *EVP_aes_256_gcm()
{
  return OPENSSL_ia32cap_P[1] & (1 << 57 - 32)?&aesni_256_gcm : &aes_256_gcm;
}

static int aes_xts_ctrl(EVP_CIPHER_CTX *c,int type,int arg,void *ptr)
{
  EVP_AES_XTS_CTX *xctx = (c -> cipher_data);
  if (type != 0) {
    return - 1;
  }
/* key1 and key2 are used as an indicator both key and IV are set */
  xctx -> xts . key1 = ((void *)0);
  xctx -> xts . key2 = ((void *)0);
  return 1;
}

static int aes_xts_init_key(EVP_CIPHER_CTX *ctx,const unsigned char *key,const unsigned char *iv,int enc)
{
  EVP_AES_XTS_CTX *xctx = (ctx -> cipher_data);
  if (!iv && !key) {
    return 1;
  }
  if (key) {
    do {
#ifdef AES_XTS_ASM
#else
      xctx -> stream = ((void *)0);
#endif
/* key_len is two AES keys */
#ifdef BSAES_CAPABLE
      if (OPENSSL_ia32cap_P[1] & (1 << 41 - 32)) {
        xctx -> stream = (enc?bsaes_xts_encrypt : bsaes_xts_decrypt);
      }
      else {
#endif
#ifdef VPAES_CAPABLE
        if (OPENSSL_ia32cap_P[1] & (1 << 41 - 32)) {
          if (enc) {
            vpaes_set_encrypt_key(key,ctx -> key_len * 4,&xctx -> ks1);
            xctx -> xts . block1 = ((block128_f )vpaes_encrypt);
          }
          else {
            vpaes_set_decrypt_key(key,ctx -> key_len * 4,&xctx -> ks1);
            xctx -> xts . block1 = ((block128_f )vpaes_decrypt);
          }
          vpaes_set_encrypt_key(key + ctx -> key_len / 2,ctx -> key_len * 4,&xctx -> ks2);
          xctx -> xts . block2 = ((block128_f )vpaes_encrypt);
          xctx -> xts . key1 = (&xctx -> ks1);
          break; 
        }
      }
#endif
      if (enc) {
        AES_set_encrypt_key(key,ctx -> key_len * 4,&xctx -> ks1);
        xctx -> xts . block1 = ((block128_f )AES_encrypt);
      }
      else {
        AES_set_decrypt_key(key,ctx -> key_len * 4,&xctx -> ks1);
        xctx -> xts . block1 = ((block128_f )AES_decrypt);
      }
      AES_set_encrypt_key(key + ctx -> key_len / 2,ctx -> key_len * 4,&xctx -> ks2);
      xctx -> xts . block2 = ((block128_f )AES_encrypt);
      xctx -> xts . key1 = (&xctx -> ks1);
    }while (0);
  }
  if (iv) {
    xctx -> xts . key2 = (&xctx -> ks2);
    memcpy((ctx -> iv),iv,16);
  }
  return 1;
}

static int aes_xts_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,const unsigned char *in,size_t len)
{
  EVP_AES_XTS_CTX *xctx = (ctx -> cipher_data);
  if (!xctx -> xts . key1 || !xctx -> xts . key2) {
    return 0;
  }
  if (!out || !in || len < 16) {
    return 0;
  }
#ifdef OPENSSL_FIPS
/* Requirement of SP800-38E */
#endif
  if (xctx -> stream) {
    ( *xctx -> stream)(in,out,len,xctx -> xts . key1,xctx -> xts . key2,(ctx -> iv));
  }
  else {
    if (CRYPTO_xts128_encrypt((&xctx -> xts),(ctx -> iv),in,out,len,ctx -> encrypt)) {
      return 0;
    }
  }
  return 1;
}
#define aes_xts_cleanup NULL
#define XTS_FLAGS	(EVP_CIPH_FLAG_DEFAULT_ASN1 | EVP_CIPH_CUSTOM_IV \
			 | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT)
static const EVP_CIPHER aesni_128_xts = {(913), (1), (((0x10001 == 0x10001?2 : 1)) * 128 / 8), (16), ((0x4000 | (0x1000 | 0x10 | 0x20 | 0x40) | 0x10001)), (aesni_xts_init_key), (aes_xts_cipher), (((void *)0)), ((sizeof(EVP_AES_XTS_CTX ))), (((void *)0)), (((void *)0)), (aes_xts_ctrl), ((void *)0)};
static const EVP_CIPHER aes_128_xts = {(913), (1), (((0x10001 == 0x10001?2 : 1)) * 128 / 8), (16), ((0x4000 | (0x1000 | 0x10 | 0x20 | 0x40) | 0x10001)), (aes_xts_init_key), (aes_xts_cipher), (((void *)0)), ((sizeof(EVP_AES_XTS_CTX ))), (((void *)0)), (((void *)0)), (aes_xts_ctrl), ((void *)0)};

const EVP_CIPHER *EVP_aes_128_xts()
{
  return OPENSSL_ia32cap_P[1] & (1 << 57 - 32)?&aesni_128_xts : &aes_128_xts;
}
static const EVP_CIPHER aesni_256_xts = {(914), (1), (((0x10001 == 0x10001?2 : 1)) * 256 / 8), (16), ((0x4000 | (0x1000 | 0x10 | 0x20 | 0x40) | 0x10001)), (aesni_xts_init_key), (aes_xts_cipher), (((void *)0)), ((sizeof(EVP_AES_XTS_CTX ))), (((void *)0)), (((void *)0)), (aes_xts_ctrl), ((void *)0)};
static const EVP_CIPHER aes_256_xts = {(914), (1), (((0x10001 == 0x10001?2 : 1)) * 256 / 8), (16), ((0x4000 | (0x1000 | 0x10 | 0x20 | 0x40) | 0x10001)), (aes_xts_init_key), (aes_xts_cipher), (((void *)0)), ((sizeof(EVP_AES_XTS_CTX ))), (((void *)0)), (((void *)0)), (aes_xts_ctrl), ((void *)0)};

const EVP_CIPHER *EVP_aes_256_xts()
{
  return OPENSSL_ia32cap_P[1] & (1 << 57 - 32)?&aesni_256_xts : &aes_256_xts;
}

static int aes_ccm_ctrl(EVP_CIPHER_CTX *c,int type,int arg,void *ptr)
{
  EVP_AES_CCM_CTX *cctx = (c -> cipher_data);
  switch(type){
    case 0x0:
{
      cctx -> key_set = 0;
      cctx -> iv_set = 0;
      cctx -> L = 8;
      cctx -> M = 12;
      cctx -> tag_set = 0;
      cctx -> len_set = 0;
      return 1;
    }
    case 0x9:
    arg = 15 - arg;
    case 0x14:
{
      if (arg < 2 || arg > 8) {
        return 0;
      }
      cctx -> L = arg;
      return 1;
    }
    case 0x11:
{
      if (arg & 1 || arg < 4 || arg > 16) {
        return 0;
      }
      if (c -> encrypt && ptr || !c -> encrypt && !ptr) {
        return 0;
      }
      if (ptr) {
        cctx -> tag_set = 1;
        memcpy((c -> buf),ptr,arg);
      }
      cctx -> M = arg;
      return 1;
    }
    case 0x10:
{
      if (!c -> encrypt || !cctx -> tag_set) {
        return 0;
      }
      if (!CRYPTO_ccm128_tag(&cctx -> ccm,ptr,((size_t )arg))) {
        return 0;
      }
      cctx -> tag_set = 0;
      cctx -> iv_set = 0;
      cctx -> len_set = 0;
      return 1;
    }
    default:
    return - 1;
  }
}

static int aes_ccm_init_key(EVP_CIPHER_CTX *ctx,const unsigned char *key,const unsigned char *iv,int enc)
{
  EVP_AES_CCM_CTX *cctx = (ctx -> cipher_data);
  if (!iv && !key) {
    return 1;
  }
  if (key) {
    do {
#ifdef VPAES_CAPABLE
      if (OPENSSL_ia32cap_P[1] & (1 << 41 - 32)) {
        vpaes_set_encrypt_key(key,ctx -> key_len * 8,&cctx -> ks);
        CRYPTO_ccm128_init(&cctx -> ccm,(cctx -> M),(cctx -> L),(&cctx -> ks),((block128_f )vpaes_encrypt));
        cctx -> str = ((void *)0);
        cctx -> key_set = 1;
        break; 
      }
#endif
      AES_set_encrypt_key(key,ctx -> key_len * 8,&cctx -> ks);
      CRYPTO_ccm128_init(&cctx -> ccm,(cctx -> M),(cctx -> L),(&cctx -> ks),((block128_f )AES_encrypt));
      cctx -> str = ((void *)0);
      cctx -> key_set = 1;
    }while (0);
  }
  if (iv) {
    memcpy((ctx -> iv),iv,(15 - cctx -> L));
    cctx -> iv_set = 1;
  }
  return 1;
}

static int aes_ccm_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,const unsigned char *in,size_t len)
{
  EVP_AES_CCM_CTX *cctx = (ctx -> cipher_data);
  CCM128_CONTEXT *ccm = &cctx -> ccm;
/* If not set up, return error */
  if (!cctx -> iv_set && !cctx -> key_set) {
    return - 1;
  }
  if (!ctx -> encrypt && !cctx -> tag_set) {
    return - 1;
  }
  if (!out) {
    if (!in) {
      if (CRYPTO_ccm128_setiv(ccm,(ctx -> iv),(15 - cctx -> L),len)) {
        return - 1;
      }
      cctx -> len_set = 1;
      return len;
    }
/* If have AAD need message length */
    if (!cctx -> len_set && len) {
      return - 1;
    }
    CRYPTO_ccm128_aad(ccm,in,len);
    return len;
  }
/* EVP_*Final() doesn't return any data */
  if (!in) {
    return 0;
  }
/* If not set length yet do it */
  if (!cctx -> len_set) {
    if (CRYPTO_ccm128_setiv(ccm,(ctx -> iv),(15 - cctx -> L),len)) {
      return - 1;
    }
    cctx -> len_set = 1;
  }
  if (ctx -> encrypt) {
    if (cctx -> str?CRYPTO_ccm128_encrypt_ccm64(ccm,in,out,len,cctx -> str) : CRYPTO_ccm128_encrypt(ccm,in,out,len)) {
      return - 1;
    }
    cctx -> tag_set = 1;
    return len;
  }
  else {
    int rv = - 1;
    if (cctx -> str?!CRYPTO_ccm128_decrypt_ccm64(ccm,in,out,len,cctx -> str) : !CRYPTO_ccm128_decrypt(ccm,in,out,len)) {
      unsigned char tag[16];
      if (CRYPTO_ccm128_tag(ccm,tag,(cctx -> M))) {
        if (!memcmp(tag,(ctx -> buf),(cctx -> M))) {
          rv = len;
        }
      }
    }
    if (rv == - 1) {
      OPENSSL_cleanse(out,len);
    }
    cctx -> iv_set = 0;
    cctx -> tag_set = 0;
    cctx -> len_set = 0;
    return rv;
  }
}
#define aes_ccm_cleanup NULL
static const EVP_CIPHER aesni_128_ccm = {(896), (1), (((0x7 == 0x10001?2 : 1)) * 128 / 8), (12), ((0x4000 | (0x1000 | 0x10 | 0x100000 | 0x20 | 0x40) | 0x7)), (aesni_ccm_init_key), (aes_ccm_cipher), (((void *)0)), ((sizeof(EVP_AES_CCM_CTX ))), (((void *)0)), (((void *)0)), (aes_ccm_ctrl), ((void *)0)};
static const EVP_CIPHER aes_128_ccm = {(896), (1), (((0x7 == 0x10001?2 : 1)) * 128 / 8), (12), ((0x4000 | (0x1000 | 0x10 | 0x100000 | 0x20 | 0x40) | 0x7)), (aes_ccm_init_key), (aes_ccm_cipher), (((void *)0)), ((sizeof(EVP_AES_CCM_CTX ))), (((void *)0)), (((void *)0)), (aes_ccm_ctrl), ((void *)0)};

const EVP_CIPHER *EVP_aes_128_ccm()
{
  return OPENSSL_ia32cap_P[1] & (1 << 57 - 32)?&aesni_128_ccm : &aes_128_ccm;
}
static const EVP_CIPHER aesni_192_ccm = {(899), (1), (((0x7 == 0x10001?2 : 1)) * 192 / 8), (12), ((0x4000 | (0x1000 | 0x10 | 0x100000 | 0x20 | 0x40) | 0x7)), (aesni_ccm_init_key), (aes_ccm_cipher), (((void *)0)), ((sizeof(EVP_AES_CCM_CTX ))), (((void *)0)), (((void *)0)), (aes_ccm_ctrl), ((void *)0)};
static const EVP_CIPHER aes_192_ccm = {(899), (1), (((0x7 == 0x10001?2 : 1)) * 192 / 8), (12), ((0x4000 | (0x1000 | 0x10 | 0x100000 | 0x20 | 0x40) | 0x7)), (aes_ccm_init_key), (aes_ccm_cipher), (((void *)0)), ((sizeof(EVP_AES_CCM_CTX ))), (((void *)0)), (((void *)0)), (aes_ccm_ctrl), ((void *)0)};

const EVP_CIPHER *EVP_aes_192_ccm()
{
  return OPENSSL_ia32cap_P[1] & (1 << 57 - 32)?&aesni_192_ccm : &aes_192_ccm;
}
static const EVP_CIPHER aesni_256_ccm = {(902), (1), (((0x7 == 0x10001?2 : 1)) * 256 / 8), (12), ((0x4000 | (0x1000 | 0x10 | 0x100000 | 0x20 | 0x40) | 0x7)), (aesni_ccm_init_key), (aes_ccm_cipher), (((void *)0)), ((sizeof(EVP_AES_CCM_CTX ))), (((void *)0)), (((void *)0)), (aes_ccm_ctrl), ((void *)0)};
static const EVP_CIPHER aes_256_ccm = {(902), (1), (((0x7 == 0x10001?2 : 1)) * 256 / 8), (12), ((0x4000 | (0x1000 | 0x10 | 0x100000 | 0x20 | 0x40) | 0x7)), (aes_ccm_init_key), (aes_ccm_cipher), (((void *)0)), ((sizeof(EVP_AES_CCM_CTX ))), (((void *)0)), (((void *)0)), (aes_ccm_ctrl), ((void *)0)};

const EVP_CIPHER *EVP_aes_256_ccm()
{
  return OPENSSL_ia32cap_P[1] & (1 << 57 - 32)?&aesni_256_ccm : &aes_256_ccm;
}
#define CENOTAPHS_MADRASSAH(x) spellbinder_snowland((void *) x)

void cataclysmically_unreservedly(int menison_irradiative,... )
{
  void *abater_inquisitorial = 0;
  va_list parallelise_eightieth;
  ++stonesoup_global_variable;;
  if (menison_irradiative > 0) {
    __builtin_va_start(parallelise_eightieth,menison_irradiative);
    abater_inquisitorial = (va_arg(parallelise_eightieth,void *));
    __builtin_va_end(parallelise_eightieth);
  }
	CENOTAPHS_MADRASSAH(abater_inquisitorial);
}

void spellbinder_snowland(void *henni_gestor)
{
    int hasCap = 0;
    int stonesoup_i = 0;
    struct stonesoup_data *stonesoupData;
  char *tenoning_midtowns = 0;
  ++stonesoup_global_variable;;
  tenoning_midtowns = ((char *)((char *)henni_gestor));
    tracepoint(stonesoup_trace, weakness_start, "CWE-765", "A", "Multiple Unlocks of a Critical Resource");
    stonesoupData = malloc(sizeof(struct stonesoup_data));
    if (stonesoupData) {
        stonesoupData->data = malloc(sizeof(char) * (strlen(tenoning_midtowns) + 1));
        stonesoupData->file1 = malloc(sizeof(char) * (strlen(tenoning_midtowns) + 1));
        stonesoupData->file2 = malloc(sizeof(char) * (strlen(tenoning_midtowns) + 1));
        if (stonesoupData->data) {
            if ((sscanf(tenoning_midtowns, "%d %s %s %s",
               &(stonesoupData->qsize),
                 stonesoupData->file1,
                 stonesoupData->file2,
                 stonesoupData->data) == 4) &&
                (strlen(stonesoupData->data) != 0))
            {
                tracepoint(stonesoup_trace, variable_signed_integral, "stonesoupData->qsize", stonesoupData->qsize, &(stonesoupData->qsize), "INITIAL-STATE");
                tracepoint(stonesoup_trace, variable_buffer, "stonesoupData->data", stonesoupData->data, "INITIAL-STATE");
                tracepoint(stonesoup_trace, variable_buffer, "stonesoupData->file1", stonesoupData->file1, "INITIAL-STATE");
                tracepoint(stonesoup_trace, variable_buffer, "stonesoupData->file2", stonesoupData->file2, "INITIAL-STATE");
               sem_init(&stonesoup_sem, 0, 1);
                stonesoupData->data_size = strlen(stonesoupData->data);
                while (stonesoupData->data[stonesoup_i] != '\0') { /* if input has capital */
                    if (stonesoupData->data[stonesoup_i] >= 'A' && /*   call function that contains */
                        stonesoupData->data[stonesoup_i] <= 'Z') { /*   weakness */
                        hasCap = 1;
                    }
                    stonesoup_i++;
                }
               tracepoint(stonesoup_trace, variable_signed_integral, "hasCap", hasCap, &hasCap, "toLower() gate");
                if (hasCap == 1) {
                    toLower(stonesoupData);
                }
                tracepoint(stonesoup_trace, trace_point, "Creating threads");
                if (pthread_create(&stonesoup_t0, NULL, reverseStr, (void *)stonesoupData) != 0) {
                    stonesoup_printf("Error creating thread 0.");
                }
                if (pthread_create(&stonesoup_t1, NULL, to1337, (void *)stonesoupData) != 0) {
                    stonesoup_printf("Error creating thread 1.");
                }
                tracepoint(stonesoup_trace, trace_point, "Joining threads");
                tracepoint(stonesoup_trace, trace_point, "Joining thread-01");
                pthread_join(stonesoup_t0, NULL);
                tracepoint(stonesoup_trace, trace_point, "Joined thread-01");
                tracepoint(stonesoup_trace, trace_point, "Joining thread-02");
                pthread_join(stonesoup_t1, NULL);
                tracepoint(stonesoup_trace, trace_point, "Joined thread-02");
                tracepoint(stonesoup_trace, trace_point, "Joined threads");
                tracepoint(stonesoup_trace, variable_signed_integral, "stonesoupData->qsize", stonesoupData->qsize, &(stonesoupData->qsize), "FINAL-STATE");
                tracepoint(stonesoup_trace, variable_buffer, "stonesoupData->data", stonesoupData->data, "FINAL-STATE");
                tracepoint(stonesoup_trace, variable_buffer, "stonesoupData->file1", stonesoupData->file1, "FINAL-STATE");
                tracepoint(stonesoup_trace, variable_buffer, "stonesoupData->file2", stonesoupData->file2, "FINAL-STATE");
                stonesoup_printf("After joins.\n");
                stonesoup_printf("String: %s\n", stonesoupData->data);
            }
            free(stonesoupData->data);
        }
        free(stonesoupData);
    } else {
        stonesoup_printf("Error parsing input.\n");
    }
    tracepoint(stonesoup_trace, weakness_end);
;
stonesoup_close_printf_context();
}
#endif
#endif

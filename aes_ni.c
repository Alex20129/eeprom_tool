/*!  \defgroup _aes_ алгоритмы шифрования AES-128

    Алгоритм применяется в режиме ECB, CBC, CTR, CFB, OFB, CMAC, CCM, GCM
ECB -- Electronic Codebook (ECB) mode
CBC -- The Cipher Block Chaining (CBC) mode
CTR -- Counter mode
CFB -- Cipher Feedback (CFB),
OFB -- Output Feedback (OFB),
CMAC-- Cipher-based MAC (MAC -- Message Authentication Code)
CCM -- Counter with CBC-MAC
GCM -- Galois/Counter mode
XTS -- XEX-based(Xor-Encrypt-Xor) Tweaked CodeBook mode (TCB) with CipherText Stealing (CTS)

    \sa [IEEE 1619.1] 1619-2007-NIST-Submission.pdf

	\see [FIPS 197] http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf

    тестирование
	\see [NIST SP 800-38A] Recommendation for Block Cipher Modes of Operation
тестовые вектора
	http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
    http://csrc.nist.gov/groups/ST/toolkit/examples.html
    http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/AES_ECB.pdf
    http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/AES_CBC.pdf
    http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/AES_CTR.pdf
    http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/AES_OFB.pdf
    http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/AES_CFB.pdf
    http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/AES_CCM.pdf
    http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/AES_GCM.pdf
    http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/AES_CMAC.pdf

Тестирование
    $ gcc -DTEST_AES -march=native -o aes aes_ni.c
 */

#include <stdint.h>
typedef struct _AES_Ctx AES_Ctx;
void AES_KeyExpansion(AES_Ctx * ctx, const uint8_t* key, int klen, int ekb);
void AES_EBC_128_encrypt(AES_Ctx*ctx, uint8_t* dst, const uint8_t* src, int length);
void AES_CBC_128_encrypt(AES_Ctx*ctx, uint8_t* dst, const uint8_t* src, int length);
void AES_EBC_128_decrypt(AES_Ctx*ctx, uint8_t* dst, const uint8_t* src, int length);
void AES_CBC_128_decrypt(AES_Ctx*ctx, uint8_t* dst, const uint8_t* src, int length);
void AES_set_iv(AES_Ctx * ctx, const uint8_t* iv, int iv_len);

#include <x86intrin.h>
typedef uint8_t  uint8x16_t __attribute__((__vector_size__(16)));
typedef int64_t  int64x2_t __attribute__((__vector_size__(16)));

typedef struct _AES_Ctx AES_Ctx;
struct _AES_Ctx {
	uint8x16_t K[10+1];
	uint8x16_t iv;
};

static inline int64x2_t AES_NI_encrypt(AES_Ctx* ctx, int64x2_t S, int rounds)
{
    int64x2_t *key = (int64x2_t*)ctx->K;
    S ^= key[0];
    S = __builtin_ia32_aesenc128(S,key[1]);
    S = __builtin_ia32_aesenc128(S,key[2]);
    S = __builtin_ia32_aesenc128(S,key[3]);
    S = __builtin_ia32_aesenc128(S,key[4]);
    S = __builtin_ia32_aesenc128(S,key[5]);
    S = __builtin_ia32_aesenc128(S,key[6]);
    S = __builtin_ia32_aesenc128(S,key[7]);
    S = __builtin_ia32_aesenc128(S,key[8]);
    S = __builtin_ia32_aesenc128(S,key[9]);
    S = __builtin_ia32_aesenclast128(S,key[10]);
    return S;
}
static inline int64x2_t AES_NI_decrypt(AES_Ctx* ctx, int64x2_t S, int rounds)
{
    int64x2_t *key = (int64x2_t*)ctx->K;
    S ^= key[0];
    S = __builtin_ia32_aesdec128(S,key[1]);
    S = __builtin_ia32_aesdec128(S,key[2]);
    S = __builtin_ia32_aesdec128(S,key[3]);
    S = __builtin_ia32_aesdec128(S,key[4]);
    S = __builtin_ia32_aesdec128(S,key[5]);
    S = __builtin_ia32_aesdec128(S,key[6]);
    S = __builtin_ia32_aesdec128(S,key[7]);
    S = __builtin_ia32_aesdec128(S,key[8]);
    S = __builtin_ia32_aesdec128(S,key[9]);
    S = __builtin_ia32_aesdeclast128(S,key[10]);
    return S;
}

void AES_EBC_128_encrypt(AES_Ctx*ctx, uint8_t* dst, const uint8_t* src, int length)
{
	const int rounds = 10;// важно чтобы это была константа 
    uint8x16_t d;
    int blocks = length>>4;
    for (int i=0;i<blocks;i++) {
        int64x2_t d = (int64x2_t)_mm_loadu_si128((const __m128i_u*)(src+i*16));
        d = AES_NI_encrypt(ctx, d, rounds);
		_mm_storeu_si128((__m128i_u*)(dst+i*16), (__m128i)d);
    }
}
void AES_CBC_128_encrypt(AES_Ctx*ctx, uint8_t* dst, const uint8_t* src, int length)
{
	const int rounds = 10;// важно чтобы это была константа 
    int64x2_t v = (int64x2_t)ctx->iv;
    int blocks = length>>4;
    for (int i=0;i<blocks;i++) {
        int64x2_t d = v^(int64x2_t)_mm_loadu_si128((const __m128i_u*)(src+i*16));
        v = AES_NI_encrypt(ctx, d, rounds);
		_mm_storeu_si128((__m128i_u*)(dst+i*16), (__m128i)v);
    }
}
void AES_EBC_128_decrypt(AES_Ctx*ctx, uint8_t* dst, const uint8_t* src, int length)
{
	const int rounds = 10;// важно чтобы это была константа 
    uint8x16_t d;
    int blocks = length>>4;
    for (int i=0;i<blocks;i++) {
        int64x2_t d = (int64x2_t)_mm_loadu_si128((const __m128i_u*)(src+i*16));
        d = AES_NI_decrypt(ctx, d, rounds);
		_mm_storeu_si128((__m128i_u*)(dst+i*16), (__m128i)d);
    }
}
void AES_CBC_128_decrypt(AES_Ctx *ctx, uint8_t* dst, const uint8_t* src, int length)
{
	const int rounds = 10;
    int i=length>>4;
    int64x2_t d,v;
	v = (int64x2_t)_mm_loadu_si128((const __m128i_u*)(src+16*i-16));
    do {
        d = AES_NI_decrypt(ctx, v, rounds);
        if ((--i)==0) break;
        v = _mm_loadu_si128((const __m128i_u*)(src+16*i-16));
		_mm_storeu_si128((__m128i_u*)(dst+i*16), d ^ v);
    } while(1);
    _mm_storeu_si128((__m128i_u*)(dst+i*16), d ^ (int64x2_t)ctx->iv);
}
#define aes_keygen_assist(a, b) \
  (uint8x16_t) _mm_aeskeygenassist_si128((__m128i) a, b)

/* AES-NI based AES key expansion based on code samples from
   Intel(r) Advanced Encryption Standard (AES) New Instructions White Paper
   (323641-001) */

static inline void aes128_key_assist (uint8x16_t * rk, uint8x16_t r)
{
  uint8x16_t t = rk[-1];
  t ^= (uint8x16_t) _mm_slli_si128((__m128i) t, 4);
  t ^= (uint8x16_t) _mm_slli_si128((__m128i) t, 4);
  t ^= (uint8x16_t) _mm_slli_si128((__m128i) t, 4);
  rk[0] = t ^ (uint8x16_t) _mm_shuffle_epi32((__m128i) r,(int)( 3 | 3 << 2 | 3 << 4 | 3 << 6));
}
static inline uint8x16_t InvMixColumn4 (uint8x16_t a) {
    return (uint8x16_t) _mm_aesimc_si128 ((__m128i) a);
}
/*! AES-128 разгибание ключа
    klen -- длина ключа 4 слова (128 бит)
 */
void AES_KeyExpansion(AES_Ctx * ctx, const uint8_t* key, int klen, int ekb)
{
    const int Nr =10;
    const uint8x16_t k = (uint8x16_t)_mm_loadu_si128((const __m128i_u*)(key));
    uint8x16_t rk[11];
    rk[0] = k;
    aes128_key_assist (rk + 1, aes_keygen_assist (rk[0], 0x01));
    aes128_key_assist (rk + 2, aes_keygen_assist (rk[1], 0x02));
    aes128_key_assist (rk + 3, aes_keygen_assist (rk[2], 0x04));
    aes128_key_assist (rk + 4, aes_keygen_assist (rk[3], 0x08));
    aes128_key_assist (rk + 5, aes_keygen_assist (rk[4], 0x10));
    aes128_key_assist (rk + 6, aes_keygen_assist (rk[5], 0x20));
    aes128_key_assist (rk + 7, aes_keygen_assist (rk[6], 0x40));
    aes128_key_assist (rk + 8, aes_keygen_assist (rk[7], 0x80));
    aes128_key_assist (rk + 9, aes_keygen_assist (rk[8], 0x1b));
    aes128_key_assist (rk +10, aes_keygen_assist (rk[9], 0x36));

    if (ekb>>16) {// сохранить в обратном порядке
        ctx->K[0] = rk[Nr];
        for (int i = 1; i < Nr; i++)
            ctx->K[i] = InvMixColumn4 (rk[Nr - i]);
        ctx->K[Nr] = rk[0];
    } else {
        ctx->K[0] = rk[0];
        for (int i = 1; i < Nr; i++)
            ctx->K[i] = rk[i];
        ctx->K[Nr] = rk[Nr];
    }
}
void AES_set_iv(AES_Ctx * ctx, const uint8_t* iv, int iv_len){
	ctx->iv = (uint8x16_t)_mm_loadu_si128((const __m128i_u*)iv);
}
#if defined(TEST_AES)
#include <stdio.h>
#include <string.h>

int main(){
	/* FIPS 197, Appendix B input */
	const uint8_t input[16] = { /* user input, unaligned buffer */
		0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
	};

    /* FIPS 197, Appendix B key */
	const uint8_t key[16] = { /* user input, unaligned buffer */
		0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x9 , 0xcf, 0x4f, 0x3c
	};
	/* FIPS 197, Appendix B expanded subkeys */
	__attribute__((aligned(4)))
	const uint8_t subkeys[11][16] = { /* library controlled, aligned buffer */
        {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x9 , 0xcf, 0x4f, 0x3c},
		{0xA0, 0xFA, 0xFE, 0x17, 0x88, 0x54, 0x2c, 0xb1, 0x23, 0xa3, 0x39, 0x39, 0x2a, 0x6c, 0x76, 0x05},
		{0xF2, 0xC2, 0x95, 0xF2, 0x7a, 0x96, 0xb9, 0x43, 0x59, 0x35, 0x80, 0x7a, 0x73, 0x59, 0xf6, 0x7f},
		{0x3D, 0x80, 0x47, 0x7D, 0x47, 0x16, 0xFE, 0x3E, 0x1E, 0x23, 0x7E, 0x44, 0x6D, 0x7A, 0x88, 0x3B},
		{0xEF, 0x44, 0xA5, 0x41, 0xA8, 0x52, 0x5B, 0x7F, 0xB6, 0x71, 0x25, 0x3B, 0xDB, 0x0B, 0xAD, 0x00},
		{0xD4, 0xD1, 0xC6, 0xF8, 0x7C, 0x83, 0x9D, 0x87, 0xCA, 0xF2, 0xB8, 0xBC, 0x11, 0xF9, 0x15, 0xBC},
		{0x6D, 0x88, 0xA3, 0x7A, 0x11, 0x0B, 0x3E, 0xFD, 0xDB, 0xF9, 0x86, 0x41, 0xCA, 0x00, 0x93, 0xFD},
		{0x4E, 0x54, 0xF7, 0x0E, 0x5F, 0x5F, 0xC9, 0xF3, 0x84, 0xA6, 0x4F, 0xB2, 0x4E, 0xA6, 0xDC, 0x4F},
		{0xEA, 0xD2, 0x73, 0x21, 0xB5, 0x8D, 0xBA, 0xD2, 0x31, 0x2B, 0xF5, 0x60, 0x7F, 0x8D, 0x29, 0x2F},
		{0xAC, 0x77, 0x66, 0xF3, 0x19, 0xFA, 0xDC, 0x21, 0x28, 0xD1, 0x29, 0x41, 0x57, 0x5c, 0x00, 0x6E},
		{0xD0, 0x14, 0xF9, 0xA8, 0xC9, 0xEE, 0x25, 0x89, 0xE1, 0x3F, 0x0c, 0xC8, 0xB6, 0x63, 0x0C, 0xA6}
	};
    struct _AES_Ctx aes_ctx;
	AES_KeyExpansion(&aes_ctx, key, 16, 128);
// проверка генерации subkeys
	for (int r = 0; r<=10; r++){
		uint8x16_t v = aes_ctx.K[r];
		for (int i = 0; i<16; i++)
			printf("0x%02X, ", v[i]);
		printf("\n");
	}
    uint8_t result[3+16*4] = { 0 };
    AES_EBC_128_encrypt(&aes_ctx, result+3, input, 16);
	/* FIPS 197, Appendix B output */
	const uint8_t exp[16] = {
		0x39, 0x25, 0x84, 0x1D, 0x02, 0xDC, 0x09, 0xFB, 0xDC, 0x11, 0x85, 0x97, 0x19, 0x6A, 0x0B, 0x32
	};

    uint8_t IV[] = {
		0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07, 0x08,0x09,0x0A,0x0B, 0x0C,0x0D,0x0E,0x0F};
    uint8_t Plaintext[] = {
        0x6B,0xC1,0xBE,0xE2, 0x2E,0x40,0x9F,0x96, 0xE9,0x3D,0x7E,0x11, 0x73,0x93,0x17,0x2A,
        0xAE,0x2D,0x8A,0x57, 0x1E,0x03,0xAC,0x9C, 0x9E,0xB7,0x6F,0xAC, 0x45,0xAF,0x8E,0x51,
        0x30,0xC8,0x1C,0x46, 0xA3,0x5C,0xE4,0x11, 0xE5,0xFB,0xC1,0x19, 0x1A,0x0A,0x52,0xEF,
        0xF6,0x9F,0x24,0x45, 0xDF,0x4F,0x9B,0x17, 0xAD,0x2B,0x41,0x7B, 0xE6,0x6C,0x37,0x10,
    };
	uint8_t Ciphertext[] = {
		0x76,0x49,0xAB,0xAC, 0x81,0x19,0xB2,0x46, 0xCE,0xE9,0x8E,0x9B, 0x12,0xE9,0x19,0x7D,
		0x50,0x86,0xCB,0x9B, 0x50,0x72,0x19,0xEE, 0x95,0xDB,0x11,0x3A, 0x91,0x76,0x78,0xB2,
		0x73,0xBE,0xD6,0xB8, 0xE3,0xC1,0x74,0x3B, 0x71,0x16,0xE6,0x9E, 0x22,0x22,0x95,0x16,
		0x3F,0xF1,0xCA,0xA1, 0x68,0x1F,0xAC,0x09, 0x12,0x0E,0xCA,0x30, 0x75,0x86,0xE1,0xA7,
	};
	if (0 == memcmp(result+3, exp, 16))
		printf("AES ECB 128 encrypt ..OK\n");
	else
		printf("..FAIL\n");

    AES_set_iv (&aes_ctx, IV, 16);
    AES_CBC_128_encrypt(&aes_ctx, result+3, Plaintext, 16*4);
    if (0) for (int i=0; i<16*4; i++) {
        printf("%02X ", result[i+3]);
        if ((i%16) == 15) printf("\n");
    }
	if (0 == memcmp(result+3, Ciphertext, 16*4))
		printf("AES CBC 128 encrypt ..OK\n");
	else
		printf("..FAIL\n");

    AES_KeyExpansion(&aes_ctx, key, 16, 128| (1u<<16));
    AES_EBC_128_decrypt(&aes_ctx, result+3, exp, 16);
	if (0 == memcmp(result+3, input, 16))
		printf("AES ECB 128 decrypt ..OK\n");
	else
		printf("..FAIL\n");
    AES_CBC_128_decrypt(&aes_ctx, result+3, Ciphertext, 16*4);
	if (0 == memcmp(result+3, Plaintext, 16*4))
		printf("AES CBC 128 decrypt ..OK\n");
	else
		printf("..FAIL\n");

    return 0;
}
#endif
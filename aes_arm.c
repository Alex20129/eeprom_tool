/*! 
 	\author _Aнатолий Георгиевский_ (https://github.com/AnatolyGeorgievski)

	 * # of rounds specified by AES:
	 * 128 bit key		10 rounds
	 * 192 bit key		12 rounds
	 * 256 bit key		14 rounds
	 * => n byte key	=> 6 + (n/4) rounds

	\see https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf

$ gcc -DTEST_AES -march=native -o aes_arm  aes_arm.c

$ gcc -DTEST_AES -march=armv8-a+crypto -o aes_arm  aes_arm.c 

$ clang --target=aarch64 -march=armv8-a+crypto -O3 -S -o aes_arm.s  aes_arm.c

Тест пропускной способности на симуляторе загрузки ядра
$ llvm-mca --march=aarch64 --mcpu=cortex-a57 -timeline aes_arm.s
 */
#include <stdint.h>
typedef struct _AES_Ctx AES_Ctx;
void AES_KeyExpansion(AES_Ctx * ctx, const uint8_t* key, int klen, int ekb);
void AES_EBC_128_encrypt(AES_Ctx*ctx, uint8_t* dst, const uint8_t* src, int length);
void AES_CBC_128_encrypt(AES_Ctx*ctx, uint8_t* dst, const uint8_t* src, int length);
void AES_EBC_128_decrypt(AES_Ctx*ctx, uint8_t* dst, const uint8_t* src, int length);
void AES_CBC_128_decrypt(AES_Ctx*ctx, uint8_t* dst, const uint8_t* src, int length);
void AES_set_iv(AES_Ctx * ctx, const uint8_t* iv, int iv_len);

typedef struct _Cipher Cipher_t;
struct _Cipher {
	const uint8_t *key;
	const uint8_t *subkeys;
	uint8_t iv[16];
};

# if defined(__ARM_NEON)
#  include <arm_neon.h>
# endif
/* GCC and LLVM Clang, but not Apple Clang */
# if defined(__ARM_ACLE) || defined(__ARM_FEATURE_CRYPTO)
#   include <arm_acle.h>
# endif

static inline uint32_t SubWord(uint32_t x)
{
	uint8x16_t v = {0};
	uint8x16_t k = vreinterpretq_u8_u32(vdupq_n_u32(x));
	v = vaeseq_u8 (v,k);
	return vgetq_lane_u32(vreinterpretq_u32_u8(v), 0);
}
static inline uint8x16_t InvMixColumns4(uint8x16_t v){
	return vaesimcq_u8(v);
}
typedef struct _AES_Ctx AES_Ctx;
struct _AES_Ctx {
	uint8x16_t K[10+1];
	uint8x16_t iv;
};

static inline uint8x16_t aes_encrypt_block(AES_Ctx * ctx, uint8x16_t v, const int nr)
{
	for (unsigned int i=0; i<nr-1; ++i)
		v = vaesmcq_u8(vaeseq_u8(v, ctx->K[i]));
	v = vaeseq_u8(v, ctx->K[nr-1]);
	return veorq_u8(v, ctx->K[nr]);
}
static inline uint8x16_t aes_decrypt_block(AES_Ctx * ctx, uint8x16_t v, const int nr)
{
	for (unsigned int i=0; i<nr-1; ++i)
		v = vaesimcq_u8(vaesdq_u8(v, ctx->K[i]));
	v = vaesdq_u8(v, ctx->K[nr-1]);
	return veorq_u8(v, ctx->K[nr]);
}

void AES_EBC_128_encrypt(AES_Ctx*ctx, uint8_t* dst, const uint8_t* src, int length)
{
	const int rounds = 10;// важно чтобы это была константа 
    uint8x16_t d;
    int blocks = length>>4;
    for (int i=0;i<blocks;i++) {
        d = vld1q_u8(src+i*16);
        d = aes_encrypt_block(ctx, d, rounds);
		vst1q_u8(dst+i*16, d);
    }
}
void AES_EBC_128_decrypt(AES_Ctx*ctx, uint8_t* dst, const uint8_t* src, int length)
{
	const int rounds = 10;// важно чтобы это была константа 
    uint8x16_t d;
    int blocks = length>>4;
    for (int i=0;i<blocks;i++) {
        d = vld1q_u8(src+i*16);
        d = aes_decrypt_block(ctx, d, rounds);
		vst1q_u8(dst+i*16, d);
    }
}
void AES_CBC_128_encrypt(AES_Ctx*ctx, uint8_t* dst, const uint8_t* src, int length)
{
	const int rounds = 10;// важно чтобы это была константа 
    uint8x16_t d, v;
    v = ctx->iv;
    int blocks = length>>4;
    for (int i=0;i<blocks;i++) {
        d = veorq_u8(v, vld1q_u8(src+i*16));
        v = aes_encrypt_block(ctx, d, rounds);
		vst1q_u8(dst+i*16, v);
    }
}
void AES_CBC_128_decrypt(AES_Ctx *ctx, uint8_t* dst, const uint8_t* src, int length)
{
	const int rounds = 10;
    int i=length>>4;
    uint8x16_t d,v;
	v = vld1q_u8(src+16*i-16);
    do {
        d = aes_decrypt_block(ctx, v, rounds);
        if ((--i)==0) break;
        v = vld1q_u8( src+16*i-16);
		vst1q_u8(dst+i*16, veorq_u8(d, v));
    } while(1);
    vst1q_u8(dst+i*16, veorq_u8(d, ctx->iv));
}

#define ROTL(x,n) ((x)<<(n)) ^ ((x)>>(32-(n)))
#define ROTR(x,n) ((x)>>(n)) ^ ((x)<<(32-(n)))

/*! AES-128 разгибание ключа
    Nk -- длина ключа 4 слова (128 бит)

	ekb - длина ключа {128, 192, 256} & 10000h - decrypt keys

	AES-128 инверсия развернутого ключа для обратного преобразования
    первый и последний ключи остаются без изменений, остальные инвертируются

 */
void AES_KeyExpansion(AES_Ctx * ctx, const uint8_t* key, int klen, int ekb)
{
    uint32_t *w = (uint32_t*)ctx->K;//,
    int Nk = (ekb&0xFFFF)/32;
    int Nbr = 4*(7+Nk);
    uint32_t rcon = 1;
    int i;
	ctx->K[0] = vld1q_u8(key);
    for (i = Nk;i < Nbr/*Nb*(Nr+1)*/; i++)
    {
        uint32_t temp = w[i-1];
        if ((i%Nk)==0)//Nk)
        {
            temp = (ROTR(SubWord(temp),8)) ^ rcon;
            rcon <<=1;
            if (rcon & 0x100) rcon ^= 0x11b;
        } else if (Nk==8 && (i&7) == 4)
        {
            temp = SubWord(temp);
        }
        w[i] = w[i-Nk] ^ temp;
    }
    if (ekb>>16) {// decrypt keys
		const int Nr = 10;
		uint8x16_t t0 = ctx->K[Nr];
		uint8x16_t t1 = ctx->K[0];
		ctx->K[0] = t0;
		ctx->K[Nr] = t1;
        for (i=1;i<Nr/2;i++){
			t0 = InvMixColumns4(ctx->K[Nr-i]);
			t1 = InvMixColumns4(ctx->K[i]);
            ctx->K[i] = t0;
            ctx->K[Nr-i] = t1;
		}
		ctx->K[Nr/2] = InvMixColumns4(ctx->K[Nr/2]);
    }
}
void AES_set_iv(AES_Ctx * ctx, const uint8_t* iv, int iv_len){
	ctx->iv = vld1q_u8(iv);
}
#if defined(TEST_AES)

#include <stdio.h>
#include <string.h>

int main(int argc, char* argv[])
{
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
	const uint8_t subkeys[10][16] = { /* library controlled, aligned buffer */
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

	/* Result */
	uint8_t result[3+16*4] = { 0 };

//	struct _Cipher ctx = {.key= key, .subkeys = (const uint8_t*)subkeys };
	struct _AES_Ctx aes_ctx;
	AES_KeyExpansion(&aes_ctx, key, 16, 128);
	AES_EBC_128_encrypt(&aes_ctx, result+3, input, 16);

	printf("Input: ");
	for (unsigned int i=0; i<16; ++i)
		printf("%02X ", input[i]);
	printf("\n");

	printf("Key: ");
	for (unsigned int i=0; i<16; ++i)
		printf("%02X ", key[i]);
	printf("\n");

	printf("Output: ");
	for (unsigned int i=3; i<19; ++i)
		printf("%02X ", result[i]);
	printf("\n");

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

/* проверка генерации subkeys
	AES_KeyExpansion(&aes_ctx, key,16, 128);

	for (int r = 0; r<=10; r++){
		uint8x16_t v = aes_ctx.K[r];
		for (int i = 0; i<16; i++)
			printf("0x%02X, ", v[i]);
		printf("\n");
	}
		*/
	return 0;
}

#endif
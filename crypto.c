#include "crypto.h"
#include "eeprom_defs.h"
#include <string.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

#define DELTA 0x9E3779B9

// XXTEA ключи для S19 (EEPROM v4/v5/v6)
static const uint8_t KEY_LARGE[4][16] = {
	"ilijnaiaayuxnixo",
	"tQ\xed|{\x5c\xd8r\x17O\xe0y\n\x15\xe4\xf5",
	"uohzoahzuhidkgna",
	"uileynimdpfnangr"
};

// XXTEA ключи для L7 (EEPROM v17)
static const uint8_t KEY_LARGE_V17[4][16] = {
	{0x4B, 0x1E, 0x5E, 0x4A, 0x3A, 0x9F, 0xB8, 0xAA,
	 0x88, 0x8A, 0x51, 0x32, 0x7F, 0xC8, 0x1B, 0xC3},

	{0x67, 0x76, 0x8F, 0x61, 0x7A, 0xC7, 0x2C, 0x3E,
	 0x7A, 0x7B, 0x12, 0xB2, 0x3B, 0xA3, 0xED, 0xFD},

	"ilijnaianayuxnixo",

	"iewgoahznehzwstg"
};

static const uint32_t KEY_SMALL[4] = {0xBABEFACE, 0xFEEDCAFE, 0xDEADBEEF, 0xABCD55AA};

static uint32_t MX(uint32_t sum, uint32_t y, uint32_t z, uint32_t p, uint32_t e, const uint32_t *k) {
	return ((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sum ^ y) + (k[(p & 3) ^ e] ^ z));
}

static void XXTEA_encode(uint32_t *v, int n, const uint32_t *k) {
	uint32_t y, z, sum;
	unsigned p, rounds, e;

	rounds = 6 + 52/n;
	sum = 0;
	z = v[n-1];
	do {
		sum += DELTA;
		e = (sum >> 2) & 3;
		for (p=0; p<n-1; p++) {
			y = v[p+1];
			z = v[p] += MX(sum, y, z, p, e, k);
		}
		y = v[0];
		z = v[n-1] += MX(sum, y, z, p, e, k);
	} while (--rounds);
}

static void XXTEA_decode(uint32_t *v, int n, const uint32_t *k) {
	uint32_t y, z, sum;
	unsigned p, rounds, e;

	rounds = 6 + 52/n;
	sum = rounds*DELTA;
	y = v[0];
	do {
		e = (sum >> 2) & 3;
		for (p=n-1; p>0; p--) {
			z = v[p-1];
			y = v[p] -= MX(sum, y, z, p, e, k);
		}
		z = v[n-1];
		y = v[0] -= MX(sum, y, z, p, e, k);
		sum -= DELTA;
	} while (--rounds);
}

void encode_data(uint8_t *data, size_t length, uint8_t algorithm_version,
				 uint8_t key_index, EEPROMVersion eeprom_version)
{
	const uint8_t (*key_large)[16] = (eeprom_version == EEPROM_VERSION_V17)
									 ? KEY_LARGE_V17
									 : KEY_LARGE;

	if (algorithm_version == CRYPTO_ALGORITHM_XXTEA)
	{
		XXTEA_encode((uint32_t*)data, length/4, (uint32_t*)key_large[key_index]);
	}
	else if (algorithm_version == CRYPTO_ALGORITHM_XOR)
	{
		uint32_t key = KEY_SMALL[key_index];
		for (size_t i = 0; i < length; i += 4)
		{
			*(uint32_t*)(data + i) ^= key;
		}
	}
}

void decode_data(uint8_t *data, size_t length, uint8_t algorithm_version,
				 uint8_t key_index, EEPROMVersion eeprom_version)
{
	const uint8_t (*key_large)[16] = (eeprom_version == EEPROM_VERSION_V17)
									 ? KEY_LARGE_V17
									 : KEY_LARGE;

	if (algorithm_version == CRYPTO_ALGORITHM_XXTEA)
	{
		XXTEA_decode((uint32_t*)data, length/4, (uint32_t*)key_large[key_index]);
	}
	else if (algorithm_version == CRYPTO_ALGORITHM_XOR)
	{
		encode_data(data, length, algorithm_version, key_index, eeprom_version);
	}
}

static const uint8_t CRC5_Lookup[256]=
{// CRC-5/BITMAIN = x5 + x2 + 1 POLY=0x5
0x00, 0x28, 0x50, 0x78, 0xA0, 0x88, 0xF0, 0xD8,
0x68, 0x40, 0x38, 0x10, 0xC8, 0xE0, 0x98, 0xB0,
0xD0, 0xF8, 0x80, 0xA8, 0x70, 0x58, 0x20, 0x08,
0xB8, 0x90, 0xE8, 0xC0, 0x18, 0x30, 0x48, 0x60,
0x88, 0xA0, 0xD8, 0xF0, 0x28, 0x00, 0x78, 0x50,
0xE0, 0xC8, 0xB0, 0x98, 0x40, 0x68, 0x10, 0x38,
0x58, 0x70, 0x08, 0x20, 0xF8, 0xD0, 0xA8, 0x80,
0x30, 0x18, 0x60, 0x48, 0x90, 0xB8, 0xC0, 0xE8,
0x38, 0x10, 0x68, 0x40, 0x98, 0xB0, 0xC8, 0xE0,
0x50, 0x78, 0x00, 0x28, 0xF0, 0xD8, 0xA0, 0x88,
0xE8, 0xC0, 0xB8, 0x90, 0x48, 0x60, 0x18, 0x30,
0x80, 0xA8, 0xD0, 0xF8, 0x20, 0x08, 0x70, 0x58,
0xB0, 0x98, 0xE0, 0xC8, 0x10, 0x38, 0x40, 0x68,
0xD8, 0xF0, 0x88, 0xA0, 0x78, 0x50, 0x28, 0x00,
0x60, 0x48, 0x30, 0x18, 0xC0, 0xE8, 0x90, 0xB8,
0x08, 0x20, 0x58, 0x70, 0xA8, 0x80, 0xF8, 0xD0,
0x70, 0x58, 0x20, 0x08, 0xD0, 0xF8, 0x80, 0xA8,
0x18, 0x30, 0x48, 0x60, 0xB8, 0x90, 0xE8, 0xC0,
0xA0, 0x88, 0xF0, 0xD8, 0x00, 0x28, 0x50, 0x78,
0xC8, 0xE0, 0x98, 0xB0, 0x68, 0x40, 0x38, 0x10,
0xF8, 0xD0, 0xA8, 0x80, 0x58, 0x70, 0x08, 0x20,
0x90, 0xB8, 0xC0, 0xE8, 0x30, 0x18, 0x60, 0x48,
0x28, 0x00, 0x78, 0x50, 0x88, 0xA0, 0xD8, 0xF0,
0x40, 0x68, 0x10, 0x38, 0xE0, 0xC8, 0xB0, 0x98,
0x48, 0x60, 0x18, 0x30, 0xE8, 0xC0, 0xB8, 0x90,
0x20, 0x08, 0x70, 0x58, 0x80, 0xA8, 0xD0, 0xF8,
0x98, 0xB0, 0xC8, 0xE0, 0x38, 0x10, 0x68, 0x40,
0xF0, 0xD8, 0xA0, 0x88, 0x50, 0x78, 0x00, 0x28,
0xC0, 0xE8, 0x90, 0xB8, 0x60, 0x48, 0x30, 0x18,
0xA8, 0x80, 0xF8, 0xD0, 0x08, 0x20, 0x58, 0x70,
0x10, 0x38, 0x40, 0x68, 0xB0, 0x98, 0xE0, 0xC8,
0x78, 0x50, 0x28, 0x00, 0xD8, 0xF0, 0x88, 0xA0,
};

static uint8_t crc5(uint8_t crc, const uint8_t *ptr, size_t bits)
{
	crc<<=3;
	int i;
	for (i=0; i< (bits>>3); i++)
		crc = CRC5_Lookup[crc ^ (*ptr++)];
	bits &= 7;
	if (bits)
	{
		crc = (crc << bits) ^ CRC5_Lookup[(crc ^ (*ptr++))>>(8-bits)];
	}
	return (crc>>3);
}

uint8_t calculate_crc(const uint8_t *ptr, size_t bits)
{
	return crc5(0xFF, ptr, bits);
}

// ═══════════════════════════════════════════════════════════════
// CRC-8
// ═══════════════════════════════════════════════════════════════
// Polynomial: 0x8C (reflected)
// Initial value: 0x00
uint8_t calculate_crc8_v1(const uint8_t *data, size_t length)
{
	uint8_t crc = 0;

	for (size_t i = 0; i < length; i++)
	{
		crc ^= data[i];

		for (int bit = 0; bit < 8; bit++)
		{
			if (crc & 1)
			{
				crc = (crc >> 1) ^ 0x8C;
			}
			else
			{
				crc = crc >> 1;
			}
		}
	}

	return crc;
}

// ═══════════════════════════════════════════════════════════════
// EEPROM v1 Crypto (AES-256-CBC for S21+)
// ═══════════════════════════════════════════════════════════════

// UTF-8 китайские ключевые фразы из ROM прошивки S21+ (0x2C4400)
// "可上九天揽月，可下五洋捉鳖" (32 байта)
static const uint8_t KEY_PHRASE_1_V1[32] =
{
	0xE5, 0x8F, 0xAF, 0xE4, 0xB8, 0x8A, 0xE4, 0xB9,
	0x9D, 0xE5, 0xA4, 0xA9, 0xE6, 0x8F, 0xBD, 0xE6,
	0x9C, 0x88, 0xEF, 0xBC, 0x8C, 0xE5, 0x8F, 0xAF,
	0xE4, 0xB8, 0x8B, 0xE4, 0xBA, 0x94, 0xE6, 0xB4
};

// "世上无难事" (16 байт)
static const uint8_t KEY_PHRASE_2_V1[16] =
{
	0xE4, 0xB8, 0x96, 0xE4, 0xB8, 0x8A, 0xE6, 0x97,
	0xA0, 0xE9, 0x9A, 0xBE, 0xE4, 0xBA, 0x8B, 0xEF
};

// DWORD-wise XOR (little-endian)
static void xor_with_key_dword(uint8_t *dst, const uint8_t *src, size_t len, uint32_t key)
{
	for (size_t i = 0; i < len; i += 4)
	{
		// Read DWORD from source (little-endian)
		uint32_t src_dword = *(const uint32_t*)(src + i);

		// XOR with key
		uint32_t dst_dword = src_dword ^ key;

		// Write back (little-endian)
		*(uint32_t*)(dst + i) = dst_dword;
	}
}

static void derive_aes_key_v1(uint32_t encryption_key, uint8_t aes_key[32], uint8_t aes_iv[16])
{
	uint8_t crypto_table_1[32];
	uint8_t crypto_table_2[16];

	xor_with_key_dword(crypto_table_1, KEY_PHRASE_1_V1, 32, encryption_key);
	xor_with_key_dword(crypto_table_2, KEY_PHRASE_2_V1, 16, encryption_key);

	uint32_t key_selector = (encryption_key % 3) + 2;

	for (size_t i = 0; i < 32; i++)
	{
		if (i > 15 || (i % key_selector) != 0)
		{
			aes_key[i] = crypto_table_1[i];
		}
		else
		{
			aes_key[i] = crypto_table_2[i];
		}
	}

	for (size_t i = 0; i < 16; i++)
	{
		if ((i % key_selector) != 0)
		{
			aes_iv[i] = crypto_table_2[i];
		}
		else
		{
			aes_iv[i] = crypto_table_1[i];
		}
	}
}

int decode_data_v1(uint8_t *data, size_t length, uint32_t encryption_key)
{
	uint8_t aes_key[32];
	uint8_t aes_iv[16];

	derive_aes_key_v1(encryption_key, aes_key, aes_iv);

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx) return -1;

	if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, aes_iv) != 1)
	{
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}

	EVP_CIPHER_CTX_set_padding(ctx, 0);

	int len;
	if (EVP_DecryptUpdate(ctx, data, &len, data, length) != 1)
	{
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}

	int final_len;
	if (EVP_DecryptFinal_ex(ctx, data + len, &final_len) != 1)
	{
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}

	EVP_CIPHER_CTX_free(ctx);

	uint8_t crypto_table_1[32];
	xor_with_key_dword(crypto_table_1, KEY_PHRASE_1_V1, 32, encryption_key);
	uint8_t xor_key = crypto_table_1[1];

	for (size_t i = 0; i < length; i++)
	{
		data[i] ^= xor_key;
	}

	return 0;
}

int encode_data_v1(uint8_t *data, size_t length, uint32_t encryption_key)
{
	uint8_t aes_key[32];
	uint8_t aes_iv[16];

	derive_aes_key_v1(encryption_key, aes_key, aes_iv);

	// XOR pre-processing
	uint8_t crypto_table_1[32];
	xor_with_key_dword(crypto_table_1, KEY_PHRASE_1_V1, 32, encryption_key);
	uint8_t xor_key = crypto_table_1[1];

	for (size_t i = 0; i < length; i++)
	{
		data[i] ^= xor_key;
	}

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx) return -1;

	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, aes_iv) != 1)
	{
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}

	EVP_CIPHER_CTX_set_padding(ctx, 0);

	int len;
	if (EVP_EncryptUpdate(ctx, data, &len, data, length) != 1)
	{
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}

	int final_len;
	if (EVP_EncryptFinal_ex(ctx, data + len, &final_len) != 1)
	{
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}

	EVP_CIPHER_CTX_free(ctx);

	return 0;
}

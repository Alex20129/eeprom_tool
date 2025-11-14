#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include "eeprom_defs.h"

void encode_data(uint8_t *data, size_t length, uint8_t algorithm_version,
				 uint8_t key_index, EEPROMVersion eeprom_version);
void decode_data(uint8_t *data, size_t length, uint8_t algorithm_version,
				 uint8_t key_index, EEPROMVersion eeprom_version);

uint8_t calculate_crc(const uint8_t *data, size_t length);

// CRC-8 for EEPROM v1
uint8_t calculate_crc8_v1(const uint8_t *data, size_t length);

// ═══════════════════════════════════════════════════════════════
// EEPROM v1 Crypto (AES-256-CBC)
// ═══════════════════════════════════════════════════════════════

// Encrypt/Decrypt for v1 (AES-256-CBC + XOR)
int encode_data_v1(uint8_t *data, size_t length, uint32_t encryption_key);
int decode_data_v1(uint8_t *data, size_t length, uint32_t encryption_key);

#endif // CRYPTO_H

#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <stddef.h>

void EncodeData(uint8_t *data, size_t length, uint8_t algorithm_version, uint8_t key_index);
void DecodeData(uint8_t *data, size_t length, uint8_t algorithm_version, uint8_t key_index);
uint8_t CalculateCRC(const uint8_t *data, size_t length);

#endif // CRYPTO_H
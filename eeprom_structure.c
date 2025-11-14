#include "eeprom_structure.h"
#include "eeprom_defs.h"
#include <string.h>
#include <stdio.h>
//#include <arpa/inet.h>
#if !defined(__BYTE_ORDER__) || (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
static inline uint16_t htons(uint16_t x){
	return __builtin_bswap16(x);
}
static inline uint16_t ntohs(uint16_t x){
	return __builtin_bswap16(x);
}
#else
static inline uint16_t htons (uint16_t a){
	return (a);// BE
}
static inline uint16_t ntohs (uint16_t a){
	return (a);// BE
}
#endif
// ═══════════════════════════════════════════════════════════════
// EEPROM v4/v5/v6 (S series)
// ═══════════════════════════════════════════════════════════════

void eeprom_to_bytes(const EEPROMStructure *eeprom, uint8_t *data)
{
	memcpy(data, eeprom, EEPROM_SIZE);
}

void eeprom_from_bytes(EEPROMStructure *eeprom, const uint8_t *data)
{
	memcpy(eeprom, data, EEPROM_SIZE);
}

// ═══════════════════════════════════════════════════════════════
// EEPROM v17 (L series)
// ═══════════════════════════════════════════════════════════════

void eeprom_v17_parse(EEPROMStructure_v17 *eeprom, const uint8_t *data)
{
	eeprom->algorithm_and_key = data[0];
	eeprom->data_length = data[1];

	memcpy(&eeprom->data,
		   data + EEPROM_V17_HEADER_SIZE,
		   EEPROM_V17_DATA_SIZE);

	eeprom->data.test_voltage = ntohs(eeprom->data.test_voltage);
	eeprom->data.test_frequency = ntohs(eeprom->data.test_frequency);
	eeprom->data.test_hashrate = ntohs(eeprom->data.test_hashrate);
}

void eeprom_v17_serialize(const EEPROMStructure_v17 *eeprom, uint8_t *data)
{
	EEPROMStructure_v17 temp;
	memcpy(&temp, eeprom, sizeof(EEPROMStructure_v17));

	temp.data.test_voltage = htons(temp.data.test_voltage);
	temp.data.test_frequency = htons(temp.data.test_frequency);
	temp.data.test_hashrate = htons(temp.data.test_hashrate);

	data[0] = temp.algorithm_and_key;
	data[1] = temp.data_length;

	memcpy(data + EEPROM_V17_HEADER_SIZE,
		   &temp.data,
		   EEPROM_V17_DATA_SIZE);
}

// ═══════════════════════════════════════════════════════════════
// EEPROM v1 (S21+ series)
// ═══════════════════════════════════════════════════════════════

void eeprom_v1_parse(EEPROMStructure_v1 *eeprom, const uint8_t *data)
{
	memcpy(eeprom, data, sizeof(EEPROMStructure_v1));
}

void eeprom_v1_serialize(const EEPROMStructure_v1 *eeprom, uint8_t *data)
{
	memcpy(data, eeprom, sizeof(EEPROMStructure_v1));
}

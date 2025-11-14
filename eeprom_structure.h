#ifndef EEPROM_STRUCTURE_H
#define EEPROM_STRUCTURE_H

#include <stdint.h>

typedef struct __attribute__((__packed__))
{
	// Header (bytes 0-1)
	uint8_t eeprom_version;              // 0
	uint8_t algorithm_and_key_version;   // 1

	// Region 1: Board Information (bytes 2-97, encrypted)
	struct __attribute__((__packed__)) {
		char board_sn[18];               // 2-19: Board serial number
		char chip_die[3];                // 20-22: Chip die version
		char chip_marking[14];           // 23-36: Chip marking
		uint8_t chip_bin;                // 37: Chip bin class
		char ft_version[10];             // 38-47: Factory test version
		uint16_t pcb_version;            // 48-49: PCB version
		uint16_t bom_version;            // 50-51: BOM version
		uint8_t asic_sensor_type;        // 52: ASIC sensor type
		uint8_t asic_sensor_addr[4];     // 53-56: ASIC sensor I2C addresses
		uint8_t pic_sensor_type;         // 57: PIC sensor type
		uint8_t pic_sensor_addr;         // 58: PIC sensor address
		char chip_tech[3];               // 59-61: Chip technology node
		char board_name[9];              // 62-70: Board name
		char factory_job[24];            // 71-94: Factory job ID
		uint8_t pt1_result;              // 95: Production test 1 result
		uint8_t pt1_count;               // 96: Production test 1 count
		uint8_t crc;                     // 97: CRC5 for this region
	} board_info;

	// Region 2: Test Parameters (bytes 98-113, encrypted)
	struct __attribute__((__packed__)) {
		uint16_t voltage;                // 98-99: PSU voltage (in 0.01V)
		uint16_t frequency;              // 100-101: Chip frequency (MHz)
		uint16_t nonce_rate;             // 102-103: Nonce rate
		int8_t pcb_temp_in;              // 104: PCB temperature input (°C)
		int8_t pcb_temp_out;             // 105: PCB temperature output (°C)
		uint8_t test_version;            // 106: Test version
		uint8_t test_standard;           // 107: Test standard
		uint8_t pt2_result;              // 108: Production test 2 result
		uint8_t pt2_count;               // 109: Production test 2 count
		uint8_t reserved[3];             // 110-112: Reserved
		uint8_t crc;                     // 113: CRC5 for this region
	} test_params;

	// Region 3: Sweep Data (bytes 114-249, encrypted, v5+ only)
	struct __attribute__((__packed__)) {
		uint16_t sweep_hashrate;         // 114-115: Sweep hashrate
		uint16_t sweep_freq_base;        // 116-117: Base frequency for sweep
		uint8_t sweep_freq_step;         // 118: Frequency step
		uint8_t sweep_level[128];        // 119-246: Per-ASIC frequency levels
		uint8_t sweep_result;            // 247: Sweep test result
		uint8_t reserved;                // 248: Reserved
		uint8_t crc;                     // 249: CRC5 for this region
	} sweep_data;

	uint8_t reserved[6];                 // 250-255: Reserved
} EEPROMStructure;

void eeprom_to_bytes(const EEPROMStructure *eeprom, uint8_t *data);
void eeprom_from_bytes(EEPROMStructure *eeprom, const uint8_t *data);

// ═══════════════════════════════════════════════════════════════
// EEPROM v17 Structure (Antminer L - 82 bytes)
// ═══════════════════════════════════════════════════════════════
typedef struct __attribute__((__packed__))
{
	// Header (2 bytes, not encrypted)
	uint8_t algorithm_and_key;         // 0x00: 0x11 = (alg=1)<<4 | (key=1)
	uint8_t data_length;               // 0x01: 80 = encrypted data length

	// Single encrypted region (bytes 2-81)
	struct __attribute__((__packed__)) {
		uint8_t subformat_version;     // 0x02: 3 = subformat version
		char serial_number[17];        // 0x03-0x13: Board serial number
		char chip_die[2];              // 0x14-0x15: Chip die version
		char chip_marking[13];         // 0x16-0x22: Chip marking
		uint8_t chip_bin;              // 0x23: Chip bin class
		char ft_program_version[9];    // 0x24-0x2C: FT Program Version
		uint8_t asic_sensor_type;      // 0x2D: ASIC sensor type
		uint8_t asic_sensor_addr[4];   // 0x2E-0x31: I2C addresses
		uint8_t pic_sensor_type;       // 0x32: PIC sensor (legacy, =0)
		uint8_t pic_sensor_addr;       // 0x33: PIC sensor address (legacy)
		uint16_t pcb_version;          // 0x34-0x35: PCB version
		uint16_t bom_version;          // 0x36-0x37: BOM version
		char chip_technology[2];       // 0x38-0x39: Technology node
		uint16_t test_voltage;         // 0x3A-0x3B: Test voltage (mV, host order)
		uint16_t test_frequency;       // 0x3C-0x3D: Test frequency (MHz, host order)
		uint16_t test_hashrate;        // 0x3E-0x3F: Hashrate * 100 (host order)
		int8_t pcb_temperature_in;     // 0x40: PCB temp input (°C)
		int8_t pcb_temperature_out;    // 0x41: PCB temp output (°C)
		uint8_t test_parameter;        // 0x42: Test parameter
		uint8_t test_result;           // 0x43: Test result (PASS/FAIL)
		char miner_type[8];            // 0x44-0x4B: Miner type / SW version
		uint8_t reserved[5];           // 0x4C-0x50: Reserved
		uint8_t crc;                   // 0x51: CRC5 checksum
	} data;
} EEPROMStructure_v17;

// Функции для работы с v17
void eeprom_v17_parse(EEPROMStructure_v17 *eeprom, const uint8_t *data);
void eeprom_v17_serialize(const EEPROMStructure_v17 *eeprom, uint8_t *data);

// ═══════════════════════════════════════════════════════════════
// EEPROM v1 Structure (Antminer S21+ - 256 bytes)
// ═══════════════════════════════════════════════════════════════
typedef struct __attribute__((__packed__))
{
	// Header (16 bytes, NOT encrypted)
	uint8_t eeprom_version;          // 0: Version = 1
	char board_name[15];             // 1-15: Board name (e.g. "A3HB70701")

	// PT1: Board Information (80 bytes, encrypted)
	struct __attribute__((__packed__)) {
		char board_serial[18];       // 0-17: Board serial number
		char factory_job[24];        // 18-41: Factory job ID
		char chip_die[3];            // 42-44: Chip die version
		char chip_marking[14];       // 45-58: Chip marking
		char ft_version[10];         // 59-68: Factory test version
		char chip_tech[3];           // 69-71: Chip technology node
		uint8_t chip_bin;            // 72: Chip bin class
		uint16_t pcb_version;        // 73-74: PCB version (little-endian)
		uint8_t bom_version;         // 75: BOM version
		uint8_t asic_sensor_type;    // 76: ASIC sensor type
		uint8_t pt1_result;          // 77: Production test 1 result
		uint8_t pt1_count;           // 78: Production test 1 count
		uint8_t crc;                 // 79: CRC5 for this block
	} pt1_data;

	// PT2: Test Parameters (16 bytes, encrypted)
	struct __attribute__((__packed__)) {
		uint16_t voltage;            // 0-1: PSU voltage (in 0.01V)
		uint16_t frequency;          // 2-3: Chip frequency (MHz)
		uint16_t nonce_rate;         // 4-5: Nonce rate (in 0.01)
		uint8_t done_type;           // 6: Done type
		int8_t temp_in;              // 7: PCB temperature input (°C)
		int8_t temp_out;             // 8: PCB temperature output (°C)
		uint8_t reserved1[2];        // 9-10: Reserved
		uint8_t pt2_result;          // 11: Production test 2 result
		uint8_t pt2_count;           // 12: Production test 2 count
		uint8_t reserved2[2];        // 13-14: Reserved
		uint8_t crc;                 // 15: CRC5 for this block
	} pt2_data;

	// SWEEP: Frequency Optimization (144 bytes, encrypted)
	// Structure unknown - storing as raw data
	uint8_t sweep_data_raw[144];     // 0-143: Raw encrypted SWEEP data (includes CRC at byte 143)
} EEPROMStructure_v1;

void eeprom_v1_parse(EEPROMStructure_v1 *eeprom, const uint8_t *data);
void eeprom_v1_serialize(const EEPROMStructure_v1 *eeprom, uint8_t *data);

#endif // EEPROM_STRUCTURE_H

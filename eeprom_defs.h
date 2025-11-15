#ifndef EEPROM_DEFS_H
#define EEPROM_DEFS_H

#include <stddef.h>
#include <stdint.h>

// ═══════════════════════════════════════════════════════════════
// Type Definitions
// ═══════════════════════════════════════════════════════════════
typedef enum
{
	EEPROM_VERSION_UNKNOWN = -1,
	EEPROM_VERSION_V1 = 1,
	EEPROM_VERSION_V4 = 4,
	EEPROM_VERSION_V5 = 5,
	EEPROM_VERSION_V6 = 6,
	EEPROM_VERSION_V17 = 17
} EEPROMVersion;

typedef enum
{
	FIELD_TYPE_UINT8,
	FIELD_TYPE_UINT16,
	FIELD_TYPE_INT8,
	FIELD_TYPE_STRING,
	FIELD_TYPE_HEX8,            // uint8_t displayed as hex
	FIELD_TYPE_HEX16,           // uint16_t displayed as hex
	FIELD_TYPE_VOLTAGE,         // uint16_t / 100 → float (V)
	FIELD_TYPE_HASHRATE,        // uint16_t / 100 → float (unit in metadata: GH/s or TH/s)
	FIELD_TYPE_ARRAY_UINT8      // Array of uint8_t
} FieldType;

// ═══════════════════════════════════════════════════════════════
// Size Constants
// ═══════════════════════════════════════════════════════════════
// Все версии используют 24C02 EEPROM - 256 байт
#define EEPROM_SIZE                256

// Фактически используемые данные
#define EEPROM_USED_SIZE_V4_V6     256
#define EEPROM_USED_SIZE_V17       82

// ═══════════════════════════════════════════════════════════════
// EEPROM v4/v5/v6 Layout (Antminer S series)
// ═══════════════════════════════════════════════════════════════

// Region 1: Board Information (v4/v5/v6)
#define EEPROM_V4_REGION1_START    2
#define EEPROM_V4_REGION1_SIZE     96
#define EEPROM_V4_REGION1_CRC_POS  97
#define EEPROM_V4_REGION1_CRC_BITS (97 * 8)  // 776 bits

// Region 2: Test Parameters (v4/v5/v6)
#define EEPROM_V4_REGION2_START    98
#define EEPROM_V4_REGION2_SIZE     16
#define EEPROM_V4_REGION2_CRC_POS  113
#define EEPROM_V4_REGION2_CRC_BITS (15 * 8)  // 120 bits

// Region 3: Sweep Data (v5/v6 only)
#define EEPROM_V5_REGION3_START    114
#define EEPROM_V5_REGION3_SIZE     136
#define EEPROM_V5_REGION3_CRC_POS  249
#define EEPROM_V5_REGION3_CRC_BITS (135 * 8)  // 1080 bits

// ═══════════════════════════════════════════════════════════════
// EEPROM v17 Layout (Antminer L)
// ═══════════════════════════════════════════════════════════════
#define EEPROM_V17_HEADER_SIZE     2
#define EEPROM_V17_DATA_SIZE       80
#define EEPROM_V17_CRC_POS         81
#define EEPROM_V17_CRC_BITS        (81 * 8)  // 648 bits

// ═══════════════════════════════════════════════════════════════
// EEPROM v1 Layout (Antminer S21+)
// ═══════════════════════════════════════════════════════════════
#define EEPROM_V1_HEADER_SIZE      16   // version (1) + board_name (15)
#define EEPROM_V1_USED_SIZE        256

// PT1: Board Information (v1)
#define EEPROM_V1_PT1_START        16
#define EEPROM_V1_PT1_SIZE         80
#define EEPROM_V1_PT1_CRC_POS      95   // 16 + 79
#define EEPROM_V1_PT1_CRC_BYTES    79   // CRC от 79 байт (16-94)

// PT2: Test Parameters (v1)
#define EEPROM_V1_PT2_START        96   // 16 + 80
#define EEPROM_V1_PT2_SIZE         16
#define EEPROM_V1_PT2_CRC_POS      111  // 96 + 15
#define EEPROM_V1_PT2_CRC_BYTES    15   // CRC от 15 байт (96-110)

// SWEEP: Frequency Optimization (v1)
#define EEPROM_V1_SWEEP_START      112  // 16 + 80 + 16
#define EEPROM_V1_SWEEP_SIZE       144
#define EEPROM_V1_SWEEP_CRC_POS    255  // 112 + 143
#define EEPROM_V1_SWEEP_CRC_BYTES  143  // CRC от 143 байт (112-254)

// v1 Encryption Keys
#define EEPROM_V1_KEY_PRODUCTION   0xAA4380BCU
#define EEPROM_V1_KEY_FIXTURE      0x34658922U

// ═══════════════════════════════════════════════════════════════
// Encryption Algorithm Constants
// ═══════════════════════════════════════════════════════════════
#define CRYPTO_ALGORITHM_XXTEA     1
#define CRYPTO_ALGORITHM_XOR       2
#define CRYPTO_ALGORITHM_AES256CBC 3

// ═══════════════════════════════════════════════════════════════
// Region Metadata System
// ═══════════════════════════════════════════════════════════════
typedef struct
{
	const char *name;              // Region name for debug output
	size_t data_start;             // Start offset in byte array
	size_t data_size;              // Size of encrypted data
	size_t crc_pos;                // CRC position in byte array
	size_t crc_bits;               // Number of bits for CRC calculation
	int test_result_pos;           // Test result position (-1 if none)
	const char *test_name;         // Test name for warnings (NULL if none)
} RegionMeta;

typedef struct
{
	EEPROMVersion version;
	const RegionMeta *regions;
	size_t region_count;
	uint8_t algorithm;             // Crypto algorithm
	uint8_t key_index;             // Key index
} EEPROMLayout;

typedef struct
{
	const char *name;              // Field name for display
	const char *category;          // Category for grouping
	FieldType type;                // Field type
	size_t offset;                 // offsetof() from structure base
	size_t size;                   // Field size in bytes
	int32_t min_value;             // Min value for validation (numeric types)
	int32_t max_value;             // Max value for validation (numeric types)
	const char *unit;              // Unit suffix (V, MHz, °C, etc)
	const char *format;            // printf format string
	uint8_t read_only;             // Cannot be edited
} FieldMetadata;

// ═══════════════════════════════════════════════════════════════
// Version Detection
// ═══════════════════════════════════════════════════════════════
static inline EEPROMVersion eeprom_detect_version(const uint8_t *data)
{
	uint8_t version_byte = data[0];

	if (version_byte == 0x11)
	{
		return EEPROM_VERSION_V17;
	}
	else if (version_byte == 1)
	{
		return EEPROM_VERSION_V1;
	}
	else if (version_byte >= 4 && version_byte <= 6)
	{
		return (EEPROMVersion)version_byte;
	}

	return EEPROM_VERSION_UNKNOWN;
}

static inline size_t eeprom_get_used_size(EEPROMVersion version)
{
	switch (version)
	{
		case EEPROM_VERSION_V1:
			return EEPROM_V1_USED_SIZE;
		case EEPROM_VERSION_V4:
		case EEPROM_VERSION_V5:
		case EEPROM_VERSION_V6:
			return EEPROM_USED_SIZE_V4_V6;
		case EEPROM_VERSION_V17:
			return EEPROM_USED_SIZE_V17;
		default:
			return 0;
	}
}

// ═══════════════════════════════════════════════════════════════
// Region Metadata Definitions
// ═══════════════════════════════════════════════════════════════

// v4/v5/v6 regions
static const RegionMeta v4_v6_regions[] =
{
	{
		.name = "Board Information",
		.data_start = EEPROM_V4_REGION1_START,
		.data_size = EEPROM_V4_REGION1_SIZE,
		.crc_pos = EEPROM_V4_REGION1_CRC_POS,
		.crc_bits = EEPROM_V4_REGION1_CRC_BITS,
		.test_result_pos = 95,  // PT1 result position
		.test_name = "PT1"
	},
	{
		.name = "Test Parameters",
		.data_start = EEPROM_V4_REGION2_START,
		.data_size = EEPROM_V4_REGION2_SIZE,
		.crc_pos = EEPROM_V4_REGION2_CRC_POS,
		.crc_bits = EEPROM_V4_REGION2_CRC_BITS,
		.test_result_pos = 108,  // PT2 result position
		.test_name = "PT2"
	},
	{
		.name = "Sweep Data",
		.data_start = EEPROM_V5_REGION3_START,
		.data_size = EEPROM_V5_REGION3_SIZE,
		.crc_pos = EEPROM_V5_REGION3_CRC_POS,
		.crc_bits = EEPROM_V5_REGION3_CRC_BITS,
		.test_result_pos = 247,  // Sweep result position
		.test_name = "Sweep"
	}
};

// v17 region
static const RegionMeta v17_regions[] =
{
	{
		.name = "Encrypted Data",
		.data_start = EEPROM_V17_HEADER_SIZE,
		.data_size = EEPROM_V17_DATA_SIZE,
		.crc_pos = EEPROM_V17_CRC_POS,
		.crc_bits = EEPROM_V17_CRC_BITS,
		.test_result_pos = 67,  // Test result position
		.test_name = "Test"
	}
};

// v1 regions (for reference; v1 uses special CRC-8 handling)
static const RegionMeta v1_regions[] =
{
	{
		.name = "PT1 (Board Info)",
		.data_start = EEPROM_V1_PT1_START,
		.data_size = EEPROM_V1_PT1_SIZE,
		.crc_pos = EEPROM_V1_PT1_CRC_POS,
		.crc_bits = EEPROM_V1_PT1_CRC_BYTES * 8,
		.test_result_pos = 93,  // 16 + 77
		.test_name = "PT1"
	},
	{
		.name = "PT2 (Test Params)",
		.data_start = EEPROM_V1_PT2_START,
		.data_size = EEPROM_V1_PT2_SIZE,
		.crc_pos = EEPROM_V1_PT2_CRC_POS,
		.crc_bits = EEPROM_V1_PT2_CRC_BYTES * 8,
		.test_result_pos = 107,  // 96 + 11
		.test_name = "PT2"
	},
	{
		.name = "SWEEP (Freq Optimization)",
		.data_start = EEPROM_V1_SWEEP_START,
		.data_size = EEPROM_V1_SWEEP_SIZE,
		.crc_pos = EEPROM_V1_SWEEP_CRC_POS,
		.crc_bits = EEPROM_V1_SWEEP_CRC_BYTES * 8,
		.test_result_pos = 253,  // 112 + 141
		.test_name = "Sweep"
	}
};

// Get layout for EEPROM version
static inline const EEPROMLayout* eeprom_get_layout(EEPROMVersion version)
{
	// Static layout definitions
	static const EEPROMLayout layouts[] =
	{
		{
			.version = EEPROM_VERSION_V1,
			.regions = v1_regions,
			.region_count = 3,
			.algorithm = CRYPTO_ALGORITHM_AES256CBC,
			.key_index = 0  // 0 = production key
		},
		{
			.version = EEPROM_VERSION_V4,
			.regions = v4_v6_regions,
			.region_count = 2,  // v4 has only 2 regions
			.algorithm = CRYPTO_ALGORITHM_XOR,
			.key_index = 0  // Will be read from data[1]
		},
		{
			.version = EEPROM_VERSION_V5,
			.regions = v4_v6_regions,
			.region_count = 3,  // v5/v6 have 3 regions
			.algorithm = CRYPTO_ALGORITHM_XOR,
			.key_index = 0
		},
		{
			.version = EEPROM_VERSION_V6,
			.regions = v4_v6_regions,
			.region_count = 3,
			.algorithm = CRYPTO_ALGORITHM_XOR,
			.key_index = 0
		},
		{
			.version = EEPROM_VERSION_V17,
			.regions = v17_regions,
			.region_count = 1,
			.algorithm = CRYPTO_ALGORITHM_XXTEA,
			.key_index = 1
		}
	};

	for (size_t i = 0; i < sizeof(layouts) / sizeof(layouts[0]); i++)
	{
		if (layouts[i].version == version)
		{
			return &layouts[i];
		}
	}

	return NULL;
}

// ═══════════════════════════════════════════════════════════════
// Field Metadata Definitions
// ═══════════════════════════════════════════════════════════════

#include "eeprom_structure.h"

// v4/v5/v6 field metadata (S series)
static const FieldMetadata eeprom_v4_v6_fields[] =
{
	// Header
	{
		.name = "EEPROM Version",
		.category = "Header",
		.type = FIELD_TYPE_UINT8,
		.offset = offsetof(EEPROMStructure, eeprom_version),
		.size = sizeof(uint8_t),
		.min_value = 4,
		.max_value = 6,
		.unit = NULL,
		.format = "%d",
		.read_only = 1
	},
	{
		.name = "Algorithm & Key",
		.category = "Header",
		.type = FIELD_TYPE_HEX8,
		.offset = offsetof(EEPROMStructure, algorithm_and_key_version),
		.size = sizeof(uint8_t),
		.min_value = 0,
		.max_value = 0xFF,
		.unit = NULL,
		.format = "0x%02X (alg=%d, key=%d)",
		.read_only = 0
	},

	// Board Information
	{
		.name = "Board Serial",
		.category = "Board Information",
		.type = FIELD_TYPE_STRING,
		.offset = offsetof(EEPROMStructure, board_info.board_sn),
		.size = 18,
		.min_value = 0,
		.max_value = 0,
		.unit = NULL,
		.format = "%.18s",
		.read_only = 0
	},
	{
		.name = "Board Name",
		.category = "Board Information",
		.type = FIELD_TYPE_STRING,
		.offset = offsetof(EEPROMStructure, board_info.board_name),
		.size = 9,
		.min_value = 0,
		.max_value = 0,
		.unit = NULL,
		.format = "%.9s",
		.read_only = 0
	},
	{
		.name = "PCB Version",
		.category = "Board Information",
		.type = FIELD_TYPE_HEX16,
		.offset = offsetof(EEPROMStructure, board_info.pcb_version),
		.size = sizeof(uint16_t),
		.min_value = 0,
		.max_value = 0xFFFF,
		.unit = NULL,
		.format = "0x%04X",
		.read_only = 0
	},
	{
		.name = "BOM Version",
		.category = "Board Information",
		.type = FIELD_TYPE_HEX16,
		.offset = offsetof(EEPROMStructure, board_info.bom_version),
		.size = sizeof(uint16_t),
		.min_value = 0,
		.max_value = 0xFFFF,
		.unit = NULL,
		.format = "0x%04X",
		.read_only = 0
	},
	{
		.name = "Chip Die",
		.category = "Board Information",
		.type = FIELD_TYPE_STRING,
		.offset = offsetof(EEPROMStructure, board_info.chip_die),
		.size = 3,
		.min_value = 0,
		.max_value = 0,
		.unit = NULL,
		.format = "%.3s",
		.read_only = 0
	},
	{
		.name = "Chip Marking",
		.category = "Board Information",
		.type = FIELD_TYPE_STRING,
		.offset = offsetof(EEPROMStructure, board_info.chip_marking),
		.size = 14,
		.min_value = 0,
		.max_value = 0,
		.unit = NULL,
		.format = "%.14s",
		.read_only = 0
	},
	{
		.name = "Chip Bin",
		.category = "Board Information",
		.type = FIELD_TYPE_UINT8,
		.offset = offsetof(EEPROMStructure, board_info.chip_bin),
		.size = sizeof(uint8_t),
		.min_value = 0,
		.max_value = 255,
		.unit = NULL,
		.format = "%d",
		.read_only = 0
	},
	{
		.name = "Chip Tech",
		.category = "Board Information",
		.type = FIELD_TYPE_STRING,
		.offset = offsetof(EEPROMStructure, board_info.chip_tech),
		.size = 3,
		.min_value = 0,
		.max_value = 0,
		.unit = NULL,
		.format = "%.3s",
		.read_only = 0
	},
	{
		.name = "FT Version",
		.category = "Board Information",
		.type = FIELD_TYPE_STRING,
		.offset = offsetof(EEPROMStructure, board_info.ft_version),
		.size = 10,
		.min_value = 0,
		.max_value = 0,
		.unit = NULL,
		.format = "%.10s",
		.read_only = 0
	},
	{
		.name = "Factory Job",
		.category = "Board Information",
		.type = FIELD_TYPE_STRING,
		.offset = offsetof(EEPROMStructure, board_info.factory_job),
		.size = 24,
		.min_value = 0,
		.max_value = 0,
		.unit = NULL,
		.format = "%.24s",
		.read_only = 0
	},
	{
		.name = "ASIC Sensor Type",
		.category = "Board Information",
		.type = FIELD_TYPE_UINT8,
		.offset = offsetof(EEPROMStructure, board_info.asic_sensor_type),
		.size = sizeof(uint8_t),
		.min_value = 0,
		.max_value = 255,
		.unit = NULL,
		.format = "%d",
		.read_only = 0
	},
	{
		.name = "PT1 Result",
		.category = "Board Information",
		.type = FIELD_TYPE_UINT8,
		.offset = offsetof(EEPROMStructure, board_info.pt1_result),
		.size = sizeof(uint8_t),
		.min_value = 0,
		.max_value = 1,
		.unit = NULL,
		.format = "%d",
		.read_only = 0
	},
	{
		.name = "PT1 Count",
		.category = "Board Information",
		.type = FIELD_TYPE_UINT8,
		.offset = offsetof(EEPROMStructure, board_info.pt1_count),
		.size = sizeof(uint8_t),
		.min_value = 0,
		.max_value = 255,
		.unit = NULL,
		.format = "%d",
		.read_only = 0
	},

	// Test Parameters
	{
		.name = "PSU Voltage",
		.category = "Test Parameters",
		.type = FIELD_TYPE_VOLTAGE,
		.offset = offsetof(EEPROMStructure, test_params.voltage),
		.size = sizeof(uint16_t),
		.min_value = 1000,
		.max_value = 1500,
		.unit = "V",
		.format = "%.2f V",
		.read_only = 0
	},
	{
		.name = "Frequency",
		.category = "Test Parameters",
		.type = FIELD_TYPE_UINT16,
		.offset = offsetof(EEPROMStructure, test_params.frequency),
		.size = sizeof(uint16_t),
		.min_value = 100,
		.max_value = 1000,
		.unit = "MHz",
		.format = "%d MHz",
		.read_only = 0
	},
	{
		.name = "Nonce Rate",
		.category = "Test Parameters",
		.type = FIELD_TYPE_UINT16,
		.offset = offsetof(EEPROMStructure, test_params.nonce_rate),
		.size = sizeof(uint16_t),
		.min_value = 0,
		.max_value = 65535,
		.unit = NULL,
		.format = "%d",
		.read_only = 0
	},
	{
		.name = "PCB Temp In",
		.category = "Test Parameters",
		.type = FIELD_TYPE_INT8,
		.offset = offsetof(EEPROMStructure, test_params.pcb_temp_in),
		.size = sizeof(int8_t),
		.min_value = -40,
		.max_value = 125,
		.unit = "°C",
		.format = "%d °C",
		.read_only = 0
	},
	{
		.name = "PCB Temp Out",
		.category = "Test Parameters",
		.type = FIELD_TYPE_INT8,
		.offset = offsetof(EEPROMStructure, test_params.pcb_temp_out),
		.size = sizeof(int8_t),
		.min_value = -40,
		.max_value = 125,
		.unit = "°C",
		.format = "%d °C",
		.read_only = 0
	},
	{
		.name = "Test Version",
		.category = "Test Parameters",
		.type = FIELD_TYPE_UINT8,
		.offset = offsetof(EEPROMStructure, test_params.test_version),
		.size = sizeof(uint8_t),
		.min_value = 0,
		.max_value = 255,
		.unit = NULL,
		.format = "%d",
		.read_only = 0
	},
	{
		.name = "Test Standard",
		.category = "Test Parameters",
		.type = FIELD_TYPE_UINT8,
		.offset = offsetof(EEPROMStructure, test_params.test_standard),
		.size = sizeof(uint8_t),
		.min_value = 0,
		.max_value = 255,
		.unit = NULL,
		.format = "%d",
		.read_only = 0
	},
	{
		.name = "PT2 Result",
		.category = "Test Parameters",
		.type = FIELD_TYPE_UINT8,
		.offset = offsetof(EEPROMStructure, test_params.pt2_result),
		.size = sizeof(uint8_t),
		.min_value = 0,
		.max_value = 1,
		.unit = NULL,
		.format = "%d",
		.read_only = 0
	},
	{
		.name = "PT2 Count",
		.category = "Test Parameters",
		.type = FIELD_TYPE_UINT8,
		.offset = offsetof(EEPROMStructure, test_params.pt2_count),
		.size = sizeof(uint8_t),
		.min_value = 0,
		.max_value = 255,
		.unit = NULL,
		.format = "%d",
		.read_only = 0
	},

	// Sweep Data (v5+ only)
	{
		.name = "Sweep Hashrate",
		.category = "Sweep Data",
		.type = FIELD_TYPE_UINT16,
		.offset = offsetof(EEPROMStructure, sweep_data.sweep_hashrate),
		.size = sizeof(uint16_t),
		.min_value = 0,
		.max_value = 65535,
		.unit = NULL,
		.format = "%d",
		.read_only = 0
	},
	{
		.name = "Sweep Freq Base",
		.category = "Sweep Data",
		.type = FIELD_TYPE_UINT16,
		.offset = offsetof(EEPROMStructure, sweep_data.sweep_freq_base),
		.size = sizeof(uint16_t),
		.min_value = 0,
		.max_value = 2000,
		.unit = "MHz",
		.format = "%d MHz",
		.read_only = 0
	},
	{
		.name = "Sweep Freq Step",
		.category = "Sweep Data",
		.type = FIELD_TYPE_UINT8,
		.offset = offsetof(EEPROMStructure, sweep_data.sweep_freq_step),
		.size = sizeof(uint8_t),
		.min_value = 0,
		.max_value = 255,
		.unit = "MHz",
		.format = "%d MHz",
		.read_only = 0
	},
	{
		.name = "ASIC Frequencies",
		.category = "Sweep Data",
		.type = FIELD_TYPE_ARRAY_UINT8,
		.offset = offsetof(EEPROMStructure, sweep_data.sweep_level),
		.size = 128,
		.min_value = 0,
		.max_value = 0,
		.unit = NULL,
		.format = NULL,
		.read_only = 1
	},
	{
		.name = "Sweep Result",
		.category = "Sweep Data",
		.type = FIELD_TYPE_UINT8,
		.offset = offsetof(EEPROMStructure, sweep_data.sweep_result),
		.size = sizeof(uint8_t),
		.min_value = 0,
		.max_value = 1,
		.unit = NULL,
		.format = "%d",
		.read_only = 0
	}
};

#define EEPROM_V4_V6_FIELD_COUNT (sizeof(eeprom_v4_v6_fields) / sizeof(eeprom_v4_v6_fields[0]))

// v17 field metadata (L series)
static const FieldMetadata eeprom_v17_fields[] =
{
	// Header
	{
		.name = "Algorithm & Key",
		.category = "Header",
		.type = FIELD_TYPE_HEX8,
		.offset = offsetof(EEPROMStructure_v17, algorithm_and_key),
		.size = sizeof(uint8_t),
		.min_value = 0,
		.max_value = 0xFF,
		.unit = NULL,
		.format = "0x%02X (alg=%d, key=%d)",
		.read_only = 1
	},
	{
		.name = "Data Length",
		.category = "Header",
		.type = FIELD_TYPE_UINT8,
		.offset = offsetof(EEPROMStructure_v17, data_length),
		.size = sizeof(uint8_t),
		.min_value = 0,
		.max_value = 255,
		.unit = "bytes",
		.format = "%d bytes",
		.read_only = 1
	},

	// Identification
	{
		.name = "Subformat Version",
		.category = "Identification",
		.type = FIELD_TYPE_UINT8,
		.offset = offsetof(EEPROMStructure_v17, data.subformat_version),
		.size = sizeof(uint8_t),
		.min_value = 0,
		.max_value = 255,
		.unit = NULL,
		.format = "%d",
		.read_only = 0
	},
	{
		.name = "Serial Number",
		.category = "Identification",
		.type = FIELD_TYPE_STRING,
		.offset = offsetof(EEPROMStructure_v17, data.serial_number),
		.size = 17,
		.min_value = 0,
		.max_value = 0,
		.unit = NULL,
		.format = "%.17s",
		.read_only = 0
	},
	{
		.name = "Chip Die",
		.category = "Identification",
		.type = FIELD_TYPE_STRING,
		.offset = offsetof(EEPROMStructure_v17, data.chip_die),
		.size = 2,
		.min_value = 0,
		.max_value = 0,
		.unit = NULL,
		.format = "%.2s",
		.read_only = 0
	},
	{
		.name = "Chip Marking",
		.category = "Identification",
		.type = FIELD_TYPE_STRING,
		.offset = offsetof(EEPROMStructure_v17, data.chip_marking),
		.size = 13,
		.min_value = 0,
		.max_value = 0,
		.unit = NULL,
		.format = "%.13s",
		.read_only = 0
	},
	{
		.name = "Chip Bin",
		.category = "Identification",
		.type = FIELD_TYPE_UINT8,
		.offset = offsetof(EEPROMStructure_v17, data.chip_bin),
		.size = sizeof(uint8_t),
		.min_value = 0,
		.max_value = 255,
		.unit = NULL,
		.format = "%d",
		.read_only = 0
	},
	{
		.name = "FT Program Version",
		.category = "Identification",
		.type = FIELD_TYPE_STRING,
		.offset = offsetof(EEPROMStructure_v17, data.ft_program_version),
		.size = 9,
		.min_value = 0,
		.max_value = 0,
		.unit = NULL,
		.format = "%.9s",
		.read_only = 0
	},
	{
		.name = "Miner Type",
		.category = "Identification",
		.type = FIELD_TYPE_STRING,
		.offset = offsetof(EEPROMStructure_v17, data.miner_type),
		.size = 8,
		.min_value = 0,
		.max_value = 0,
		.unit = NULL,
		.format = "%.8s",
		.read_only = 0
	},

	// Hardware Versions
	{
		.name = "PCB Version",
		.category = "Hardware",
		.type = FIELD_TYPE_HEX16,
		.offset = offsetof(EEPROMStructure_v17, data.pcb_version),
		.size = sizeof(uint16_t),
		.min_value = 0,
		.max_value = 0xFFFF,
		.unit = NULL,
		.format = "%d.%02d",
		.read_only = 0
	},
	{
		.name = "BOM Version",
		.category = "Hardware",
		.type = FIELD_TYPE_HEX16,
		.offset = offsetof(EEPROMStructure_v17, data.bom_version),
		.size = sizeof(uint16_t),
		.min_value = 0,
		.max_value = 0xFFFF,
		.unit = NULL,
		.format = "%d.%d",
		.read_only = 0
	},
	{
		.name = "Chip Technology",
		.category = "Hardware",
		.type = FIELD_TYPE_STRING,
		.offset = offsetof(EEPROMStructure_v17, data.chip_technology),
		.size = 2,
		.min_value = 0,
		.max_value = 0,
		.unit = NULL,
		.format = "%.2s",
		.read_only = 0
	},
	{
		.name = "ASIC Sensor Type",
		.category = "Hardware",
		.type = FIELD_TYPE_UINT8,
		.offset = offsetof(EEPROMStructure_v17, data.asic_sensor_type),
		.size = sizeof(uint8_t),
		.min_value = 0,
		.max_value = 255,
		.unit = NULL,
		.format = "%d",
		.read_only = 0
	},

	// Test Parameters
	{
		.name = "Test Voltage",
		.category = "Test Parameters",
		.type = FIELD_TYPE_UINT16,
		.offset = offsetof(EEPROMStructure_v17, data.test_voltage),
		.size = sizeof(uint16_t),
		.min_value = 8000,
		.max_value = 14000,
		.unit = "mV",
		.format = "%d mV",
		.read_only = 0
	},
	{
		.name = "Test Frequency",
		.category = "Test Parameters",
		.type = FIELD_TYPE_UINT16,
		.offset = offsetof(EEPROMStructure_v17, data.test_frequency),
		.size = sizeof(uint16_t),
		.min_value = 100,
		.max_value = 2000,
		.unit = "MHz",
		.format = "%d MHz",
		.read_only = 0
	},
	{
		.name = "Test Hashrate",
		.category = "Test Parameters",
		.type = FIELD_TYPE_HASHRATE,
		.offset = offsetof(EEPROMStructure_v17, data.test_hashrate),
		.size = sizeof(uint16_t),
		.min_value = 0,
		.max_value = 10000,
		.unit = "GH/s",
		.format = "%.2f GH/s",
		.read_only = 0
	},
	{
		.name = "PCB Temp In",
		.category = "Test Parameters",
		.type = FIELD_TYPE_INT8,
		.offset = offsetof(EEPROMStructure_v17, data.pcb_temperature_in),
		.size = sizeof(int8_t),
		.min_value = -40,
		.max_value = 125,
		.unit = "°C",
		.format = "%d °C",
		.read_only = 0
	},
	{
		.name = "PCB Temp Out",
		.category = "Test Parameters",
		.type = FIELD_TYPE_INT8,
		.offset = offsetof(EEPROMStructure_v17, data.pcb_temperature_out),
		.size = sizeof(int8_t),
		.min_value = -40,
		.max_value = 125,
		.unit = "°C",
		.format = "%d °C",
		.read_only = 0
	},
	{
		.name = "Test Parameter",
		.category = "Test Parameters",
		.type = FIELD_TYPE_UINT8,
		.offset = offsetof(EEPROMStructure_v17, data.test_parameter),
		.size = sizeof(uint8_t),
		.min_value = 0,
		.max_value = 255,
		.unit = NULL,
		.format = "%d",
		.read_only = 0
	},
	{
		.name = "Test Result",
		.category = "Test Parameters",
		.type = FIELD_TYPE_UINT8,
		.offset = offsetof(EEPROMStructure_v17, data.test_result),
		.size = sizeof(uint8_t),
		.min_value = 0,
		.max_value = 1,
		.unit = NULL,
		.format = "%d",
		.read_only = 0
	}
};

#define EEPROM_V17_FIELD_COUNT (sizeof(eeprom_v17_fields) / sizeof(eeprom_v17_fields[0]))

// v1 field metadata (S21+ series)
static const FieldMetadata eeprom_v1_fields[] =
{
	// Header
	{
		.name = "EEPROM Version",
		.category = "Header",
		.type = FIELD_TYPE_UINT8,
		.offset = offsetof(EEPROMStructure_v1, eeprom_version),
		.size = sizeof(uint8_t),
		.min_value = 1,
		.max_value = 1,
		.unit = NULL,
		.format = "%d",
		.read_only = 1
	},
	{
		.name = "Board Name",
		.category = "Header",
		.type = FIELD_TYPE_STRING,
		.offset = offsetof(EEPROMStructure_v1, board_name),
		.size = 15,
		.min_value = 0,
		.max_value = 0,
		.unit = NULL,
		.format = "%.15s",
		.read_only = 0
	},

	// PT1: Board Information
	{
		.name = "Board Serial",
		.category = "Board Information",
		.type = FIELD_TYPE_STRING,
		.offset = offsetof(EEPROMStructure_v1, pt1_data.board_serial),
		.size = 18,
		.min_value = 0,
		.max_value = 0,
		.unit = NULL,
		.format = "%.18s",
		.read_only = 0
	},
	{
		.name = "Factory Job",
		.category = "Board Information",
		.type = FIELD_TYPE_STRING,
		.offset = offsetof(EEPROMStructure_v1, pt1_data.factory_job),
		.size = 24,
		.min_value = 0,
		.max_value = 0,
		.unit = NULL,
		.format = "%.24s",
		.read_only = 0
	},
	{
		.name = "Chip Die",
		.category = "Board Information",
		.type = FIELD_TYPE_STRING,
		.offset = offsetof(EEPROMStructure_v1, pt1_data.chip_die),
		.size = 3,
		.min_value = 0,
		.max_value = 0,
		.unit = NULL,
		.format = "%.3s",
		.read_only = 0
	},
	{
		.name = "Chip Marking",
		.category = "Board Information",
		.type = FIELD_TYPE_STRING,
		.offset = offsetof(EEPROMStructure_v1, pt1_data.chip_marking),
		.size = 14,
		.min_value = 0,
		.max_value = 0,
		.unit = NULL,
		.format = "%.14s",
		.read_only = 0
	},
	{
		.name = "FT Version",
		.category = "Board Information",
		.type = FIELD_TYPE_STRING,
		.offset = offsetof(EEPROMStructure_v1, pt1_data.ft_version),
		.size = 10,
		.min_value = 0,
		.max_value = 0,
		.unit = NULL,
		.format = "%.10s",
		.read_only = 0
	},
	{
		.name = "Chip Tech",
		.category = "Board Information",
		.type = FIELD_TYPE_STRING,
		.offset = offsetof(EEPROMStructure_v1, pt1_data.chip_tech),
		.size = 3,
		.min_value = 0,
		.max_value = 0,
		.unit = NULL,
		.format = "%.3s",
		.read_only = 0
	},
	{
		.name = "Chip Bin",
		.category = "Board Information",
		.type = FIELD_TYPE_UINT8,
		.offset = offsetof(EEPROMStructure_v1, pt1_data.chip_bin),
		.size = sizeof(uint8_t),
		.min_value = 0,
		.max_value = 255,
		.unit = NULL,
		.format = "%d",
		.read_only = 0
	},
	{
		.name = "PCB Version",
		.category = "Board Information",
		.type = FIELD_TYPE_HEX16,
		.offset = offsetof(EEPROMStructure_v1, pt1_data.pcb_version),
		.size = sizeof(uint16_t),
		.min_value = 0,
		.max_value = 0xFFFF,
		.unit = NULL,
		.format = "0x%04X",
		.read_only = 0
	},
	{
		.name = "BOM Version",
		.category = "Board Information",
		.type = FIELD_TYPE_UINT8,
		.offset = offsetof(EEPROMStructure_v1, pt1_data.bom_version),
		.size = sizeof(uint8_t),
		.min_value = 0,
		.max_value = 255,
		.unit = NULL,
		.format = "%d",
		.read_only = 0
	},
	{
		.name = "ASIC Sensor Type",
		.category = "Board Information",
		.type = FIELD_TYPE_UINT8,
		.offset = offsetof(EEPROMStructure_v1, pt1_data.asic_sensor_type),
		.size = sizeof(uint8_t),
		.min_value = 0,
		.max_value = 255,
		.unit = NULL,
		.format = "%d",
		.read_only = 0
	},
	{
		.name = "PT1 Result",
		.category = "Board Information",
		.type = FIELD_TYPE_UINT8,
		.offset = offsetof(EEPROMStructure_v1, pt1_data.pt1_result),
		.size = sizeof(uint8_t),
		.min_value = 0,
		.max_value = 1,
		.unit = NULL,
		.format = "%d",
		.read_only = 0
	},
	{
		.name = "PT1 Count",
		.category = "Board Information",
		.type = FIELD_TYPE_UINT8,
		.offset = offsetof(EEPROMStructure_v1, pt1_data.pt1_count),
		.size = sizeof(uint8_t),
		.min_value = 0,
		.max_value = 255,
		.unit = NULL,
		.format = "%d",
		.read_only = 0
	},

	// PT2: Test Parameters
	{
		.name = "PSU Voltage",
		.category = "Test Parameters",
		.type = FIELD_TYPE_VOLTAGE,
		.offset = offsetof(EEPROMStructure_v1, pt2_data.voltage),
		.size = sizeof(uint16_t),
		.min_value = 1000,
		.max_value = 1500,
		.unit = "V",
		.format = "%.2f V",
		.read_only = 0
	},
	{
		.name = "Frequency",
		.category = "Test Parameters",
		.type = FIELD_TYPE_UINT16,
		.offset = offsetof(EEPROMStructure_v1, pt2_data.frequency),
		.size = sizeof(uint16_t),
		.min_value = 100,
		.max_value = 1000,
		.unit = "MHz",
		.format = "%d MHz",
		.read_only = 0
	},
	{
		.name = "Nonce Rate",
		.category = "Test Parameters",
		.type = FIELD_TYPE_UINT16,
		.offset = offsetof(EEPROMStructure_v1, pt2_data.nonce_rate),
		.size = sizeof(uint16_t),
		.min_value = 0,
		.max_value = 65535,
		.unit = NULL,
		.format = "%.2f",
		.read_only = 0
	},
	{
		.name = "Done Type",
		.category = "Test Parameters",
		.type = FIELD_TYPE_UINT8,
		.offset = offsetof(EEPROMStructure_v1, pt2_data.done_type),
		.size = sizeof(uint8_t),
		.min_value = 0,
		.max_value = 255,
		.unit = NULL,
		.format = "%d",
		.read_only = 0
	},
	{
		.name = "PCB Temp In",
		.category = "Test Parameters",
		.type = FIELD_TYPE_INT8,
		.offset = offsetof(EEPROMStructure_v1, pt2_data.temp_in),
		.size = sizeof(int8_t),
		.min_value = -40,
		.max_value = 125,
		.unit = "°C",
		.format = "%d °C",
		.read_only = 0
	},
	{
		.name = "PCB Temp Out",
		.category = "Test Parameters",
		.type = FIELD_TYPE_INT8,
		.offset = offsetof(EEPROMStructure_v1, pt2_data.temp_out),
		.size = sizeof(int8_t),
		.min_value = -40,
		.max_value = 125,
		.unit = "°C",
		.format = "%d °C",
		.read_only = 0
	},
	{
		.name = "PT2 Result",
		.category = "Test Parameters",
		.type = FIELD_TYPE_UINT8,
		.offset = offsetof(EEPROMStructure_v1, pt2_data.pt2_result),
		.size = sizeof(uint8_t),
		.min_value = 0,
		.max_value = 1,
		.unit = NULL,
		.format = "%d",
		.read_only = 0
	},
	{
		.name = "PT2 Count",
		.category = "Test Parameters",
		.type = FIELD_TYPE_UINT8,
		.offset = offsetof(EEPROMStructure_v1, pt2_data.pt2_count),
		.size = sizeof(uint8_t),
		.min_value = 0,
		.max_value = 255,
		.unit = NULL,
		.format = "%d",
		.read_only = 0
	},

	// SWEEP: Frequency Optimization
	{
		.name = "SWEEP Voltage",
		.category = "Sweep Data",
		.type = FIELD_TYPE_VOLTAGE,
		.offset = offsetof(EEPROMStructure_v1, sweep_data.voltage),
		.size = sizeof(uint16_t),
		.min_value = 1000,
		.max_value = 1500,
		.unit = "V",
		.format = "%.2f V",
		.read_only = 0
	},
	{
		.name = "Sweep Hashrate",
		.category = "Sweep Data",
		.type = FIELD_TYPE_HASHRATE,
		.offset = offsetof(EEPROMStructure_v1, sweep_data.sweep_hashrate),
		.size = sizeof(uint16_t),
		.min_value = 0,
		.max_value = 65535,
		.unit = "TH/s",
		.format = "%.2f TH/s",
		.read_only = 0
	},
	{
		.name = "Sweep Freq Base",
		.category = "Sweep Data",
		.type = FIELD_TYPE_UINT16,
		.offset = offsetof(EEPROMStructure_v1, sweep_data.sweep_freq_base),
		.size = sizeof(uint16_t),
		.min_value = 0,
		.max_value = 2000,
		.unit = "MHz",
		.format = "%d MHz",
		.read_only = 0
	},
	{
		.name = "Sweep Freq Step",
		.category = "Sweep Data",
		.type = FIELD_TYPE_UINT8,
		.offset = offsetof(EEPROMStructure_v1, sweep_data.sweep_freq_step),
		.size = sizeof(uint8_t),
		.min_value = 0,
		.max_value = 255,
		.unit = "MHz",
		.format = "%d MHz",
		.read_only = 0
	},
	{
		.name = "ASIC Frequencies",
		.category = "Sweep Data",
		.type = FIELD_TYPE_ARRAY_UINT8,
		.offset = offsetof(EEPROMStructure_v1, sweep_data.sweep_level),
		.size = 128,
		.min_value = 0,
		.max_value = 0,
		.unit = NULL,
		.format = NULL,
		.read_only = 1
	},
	{
		.name = "Sweep Result",
		.category = "Sweep Data",
		.type = FIELD_TYPE_UINT8,
		.offset = offsetof(EEPROMStructure_v1, sweep_data.sweep_result),
		.size = sizeof(uint8_t),
		.min_value = 0,
		.max_value = 1,
		.unit = NULL,
		.format = "%d",
		.read_only = 0
	},
	{
		.name = "Sweep Count",
		.category = "Sweep Data",
		.type = FIELD_TYPE_UINT8,
		.offset = offsetof(EEPROMStructure_v1, sweep_data.sweep_count),
		.size = sizeof(uint8_t),
		.min_value = 0,
		.max_value = 255,
		.unit = NULL,
		.format = "%d",
		.read_only = 0
	}

};

#define EEPROM_V1_FIELD_COUNT (sizeof(eeprom_v1_fields) / sizeof(eeprom_v1_fields[0]))

// Get field metadata for EEPROM version
static inline const FieldMetadata* eeprom_get_fields(EEPROMVersion version, size_t *count)
{
	switch (version)
	{
		case EEPROM_VERSION_V1:
			if (count) *count = EEPROM_V1_FIELD_COUNT;
			return eeprom_v1_fields;

		case EEPROM_VERSION_V4:
		case EEPROM_VERSION_V5:
		case EEPROM_VERSION_V6:
			if (count) *count = EEPROM_V4_V6_FIELD_COUNT;
			return eeprom_v4_v6_fields;

		case EEPROM_VERSION_V17:
			if (count) *count = EEPROM_V17_FIELD_COUNT;
			return eeprom_v17_fields;

		default:
			if (count) *count = 0;
			return NULL;
	}
}

#endif // EEPROM_DEFS_H

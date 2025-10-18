#ifndef EEPROM_STRUCTURE_H
#define EEPROM_STRUCTURE_H

#include <stdint.h>

typedef struct __attribute__((__packed__))
{
    uint8_t eeprom_version;           // 0
    uint8_t algorithm_and_key_version;    // 1
    char board_sn[18];                    // 2-19
    char chip_die[3];                     // 20-22
    char chip_marking[14];                // 23-36
    uint8_t chip_bin;                     // 37
    char ft_version[10];                  // 38-47
    uint16_t pcb_version;                 // 48-49
    uint16_t bom_version;                 // 50-51
    uint8_t asic_sensor_type;             // 52
    uint8_t asic_sensor_addr[4];          // 53-56
    uint8_t pic_sensor_type;              // 57
    uint8_t pic_sensor_addr;              // 58
    char chip_tech[3];                    // 59-61
    char board_name[9];                   // 62-70
    char factory_job[24];                 // 71-94
    uint8_t pt1_result;                   // 95
    uint8_t pt1_count;                    // 96
    uint8_t board_info_crc;               // 97
    uint16_t voltage;                     // 98-99
    uint16_t frequency;                   // 100-101
    uint16_t nonce_rate;                  // 102-103
    int8_t pcb_temp_in;                   // 104
    int8_t pcb_temp_out;                  // 105
    uint8_t test_version;                 // 106
    uint8_t test_standard;                // 107
    uint8_t pt2_result;                   // 108
    uint8_t pt2_count;                    // 109
    uint8_t reserved[3];                  // 110-112
    uint8_t param_info_crc;               // 113
    uint16_t sweep_hashrate;              // 114-115
    uint16_t reserved2;                   // 116-117
    uint8_t reserved3;                    // 118
    uint32_t sweep_data[32];              // 119-246
    uint8_t sweep_result;                 // 247
    uint8_t reserved4;                    // 248
    uint8_t sweep_crc;                    // 249
    uint8_t reserved5[6];                 // 250-255
} EEPROMStructure;

void eeprom_to_bytes(const EEPROMStructure *eeprom, uint8_t *data);
void eeprom_from_bytes(EEPROMStructure *eeprom, const uint8_t *data);
void print_eeprom_structure(const EEPROMStructure *eeprom);

#endif // EEPROM_STRUCTURE_H

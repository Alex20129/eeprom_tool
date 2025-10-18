#include "eeprom_structure.h"
#include <string.h>
#include <stdio.h>

void eeprom_to_bytes(const EEPROMStructure *eeprom, uint8_t *data)
{
	memcpy(data, eeprom, 256);
}

void eeprom_from_bytes(EEPROMStructure *eeprom, const uint8_t *data)
{
	memcpy(eeprom, data, 256);
}

void print_eeprom_structure(const EEPROMStructure *eeprom)
{
    printf("Eeprom Version: %d\n", eeprom->eeprom_version);
    printf("Algorithm Version: %d\n", eeprom->algorithm_and_key_version >> 4);
    printf("Key Version: %d\n", eeprom->algorithm_and_key_version & 0xF);
    printf("Board SN: %.18s\n", eeprom->board_sn);
    printf("Chip Die: %.3s\n", eeprom->chip_die);
    printf("Chip Marking: %.14s\n", eeprom->chip_marking);
    printf("Chip Bin: %d\n", eeprom->chip_bin);
    printf("FT Version: %.10s\n", eeprom->ft_version);
    printf("PCB Version: %d\n", eeprom->pcb_version);
    printf("BOM Version: %d\n", eeprom->bom_version);
    printf("ASIC Sensor Type: %d\n", eeprom->asic_sensor_type);
    printf("ASIC Sensor Addresses: %d %d %d %d\n", 
           eeprom->asic_sensor_addr[0], eeprom->asic_sensor_addr[1],
           eeprom->asic_sensor_addr[2], eeprom->asic_sensor_addr[3]);
    printf("PIC Sensor Type: %d\n", eeprom->pic_sensor_type);
    printf("PIC Sensor Address: %d\n", eeprom->pic_sensor_addr);
    printf("Chip Tech: %.3s\n", eeprom->chip_tech);
    printf("Board Name: %.9s\n", eeprom->board_name);
    printf("Factory Job: %.24s\n", eeprom->factory_job);
    printf("PT1 Result: %d\n", eeprom->pt1_result);
    printf("PT1 Count: %d\n", eeprom->pt1_count);
    printf("Board Info CRC: %d\n", eeprom->board_info_crc);
    printf("Voltage: %d\n", eeprom->voltage);
    printf("Frequency: %d\n", eeprom->frequency);
    printf("Nonce Rate: %d\n", eeprom->nonce_rate);
    printf("PCB Temp In: %d\n", eeprom->pcb_temp_in);
    printf("PCB Temp Out: %d\n", eeprom->pcb_temp_out);
    printf("Test Version: %d\n", eeprom->test_version);
    printf("Test Standard: %d\n", eeprom->test_standard);
    printf("PT2 Result: %d\n", eeprom->pt2_result);
    printf("PT2 Count: %d\n", eeprom->pt2_count);
    printf("Param Info CRC: %d\n", eeprom->param_info_crc);
    printf("Sweep Hashrate: %d\n", eeprom->sweep_hashrate);
    printf("Sweep Data:");
    for (int i = 0; i < 32; i++) {
        if (i % 8 == 0) printf("\n  ");
        printf("%08X ", eeprom->sweep_data[i]);
    }
    printf("\nSweep Result: %d\n", eeprom->sweep_result);
    printf("Sweep CRC: %d\n", eeprom->sweep_crc);
}

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
    printf("EEPROM Ver. : %d\n", eeprom->eeprom_version);
    printf("Alg Version : %d\n", eeprom->algorithm_and_key_version >> 4);
    printf("Key Version : %d\n", eeprom->algorithm_and_key_version & 0xF);

    printf("Board Serial: %.18s\n", eeprom->board_sn);
    printf("Board Name  : %.9s\n", eeprom->board_name);
    printf("PCB Version : %d\n", eeprom->pcb_version);
    printf("BOM Version : %d\n", eeprom->bom_version);
    printf("Chip Die    : %.3s\n", eeprom->chip_die);
    printf("Chip Tech   : %.3s\n", eeprom->chip_tech);
    printf("Chip Marking: %.14s\n", eeprom->chip_marking);
    printf("Chip Bin    : %d\n", eeprom->chip_bin);
    printf("ASIC Sensor Type: %d\n", eeprom->asic_sensor_type);
    printf("ASIC Sensor Address: %X %X %X %X\n", 
           eeprom->asic_sensor_addr[0], eeprom->asic_sensor_addr[1],
           eeprom->asic_sensor_addr[2], eeprom->asic_sensor_addr[3]);
    printf("PIC  Sensor Type: %d\n", eeprom->pic_sensor_type);
    printf("PIC  Sensor Address: %d\n", eeprom->pic_sensor_addr);

    printf("Factory Job : %.24s\n",eeprom->factory_job);
    printf("FT  Version : %.10s\n", eeprom->ft_version);
    printf("PT1 Result  : %d\n",   eeprom->pt1_result);
    printf("PT1 Count   : %d\n",   eeprom->pt1_count);
    printf("Brd Info CRC: %X\n", eeprom->board_info_crc);

    printf("PSU Voltage : %1.2f V\n", (float)eeprom->voltage/100);
    printf("Frequency   : %d MHz\n", eeprom->frequency);
    printf("Nonce Rate  : %d\n", eeprom->nonce_rate);
    printf("PCB Temp In : %d\n", eeprom->pcb_temp_in);
    printf("PCB Temp Out: %d\n", eeprom->pcb_temp_out);
    printf("Test Version: %d\n", eeprom->test_version);
    printf("Tst Standard: %d\n",eeprom->test_standard);
    printf("PT2 Result  : %d\n", eeprom->pt2_result);
    printf("PT2 Count   : %d\n", eeprom->pt2_count);
    printf("PT2 Info CRC: %X\n", eeprom->param_info_crc);

    if (eeprom->eeprom_version>4) {
        printf("Sweep H.rate: %d\n", eeprom->sweep_hashrate);
        printf("Sweep Data  :");
        for (int i = 0; i < 32; i++) {
            if (i % 8 == 0) printf("\n  ");
            printf("%08X ", eeprom->sweep_data[i]);
        }
        printf("\nSweep Result: %d\n", eeprom->sweep_result);
        printf("Sweep CRC   : %X\n", eeprom->sweep_crc);
    }
}

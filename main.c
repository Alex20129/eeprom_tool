#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "eeprom_structure.h"
#include "crypto.h"

#define EEPROM_SIZE 256
#define MAX_FILENAME 256

// Function prototypes
static int read_file(const char *filename, uint8_t *data, size_t size);
static int write_file(const char *filename, const uint8_t *data, size_t size);
static void decode_eeprom_v4(uint8_t *data, size_t dataSize);
static void decode_eeprom_v5(uint8_t *data, size_t dataSize);
static void encode_eeprom_v4(uint8_t *data, size_t dataSize);
static void encode_eeprom_v5(uint8_t *data, size_t dataSize);
static void decode_and_print_eeprom(uint8_t *data, size_t dataSize);
static void edit_eeprom(EEPROMStructure *eeprom);
static void encode_and_save_eeprom(const char *filename, EEPROMStructure *eeprom);

static int read_file(const char *filename, uint8_t *data, size_t size) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        printf("Error: Cannot open file %s\n", filename);
        return 0;
    }

    size_t read_size = fread(data, 1, size, file);
    fclose(file);

    if (read_size != size) {
        printf("Error: File size mismatch. Expected %zu bytes, read %zu bytes\n", size, read_size);
        return 0;
    }

    return 1;
}

static int write_file(const char *filename, const uint8_t *data, size_t size) {
    FILE *file = fopen(filename, "wb");
    if (!file) {
        printf("Error: Cannot open file %s for writing\n", filename);
        return 0;
    }

    size_t written_size = fwrite(data, 1, size, file);
    fclose(file);

    if (written_size != size) {
        printf("Error: Failed to write all data. Wrote %zu of %zu bytes\n", written_size, size);
        return 0;
    }

    return 1;
}

static void decode_eeprom_v4(uint8_t *data, size_t dataSize) {
    uint8_t algorithm_version = data[1] >> 4;
    uint8_t key_index = data[1] & 0xF;

    // Decode Region 1 (bytes 2-97)
    DecodeData(data + 2, 96, algorithm_version, key_index);
    uint8_t region1_crc = CalculateCRC(data, 776);  // 776 bits = 97 bytes
    if (region1_crc != data[97]) {
        printf("Warning: CRC mismatch in Region 1. Calculated: %d, Stored: %d\n", region1_crc, data[97]);
    }
    if (data[95] != 1) {
        printf("Warning: PT1 test did not pass\n");
    }

    // Decode Region 2 (bytes 98-113)
    DecodeData(data + 98, 16, algorithm_version, key_index);
    uint8_t region2_crc = CalculateCRC(data + 98, 120);  // 120 bits = 15 bytes
    if (region2_crc != data[113]) {
        printf("Warning: CRC mismatch in Region 2. Calculated: %d, Stored: %d\n", region2_crc, data[113]);
    }
    if (data[108] != 1) {
        printf("Warning: PT2 test did not pass\n");
    }
}

static void decode_eeprom_v5(uint8_t *data, size_t dataSize) {
    uint8_t algorithm_version = data[1] >> 4;
    uint8_t key_index = data[1] & 0xF;

    // Decode Region 1 (bytes 2-97)
    DecodeData(data + 2, 96, algorithm_version, key_index);
    uint8_t region1_crc = CalculateCRC(data, 776);  // 776 bits = 97 bytes
    if (region1_crc != data[97]) {
        printf("Warning: CRC mismatch in Region 1. Calculated: %d, Stored: %d\n", region1_crc, data[97]);
    }
    if (data[95] != 1) {
        printf("Warning: PT1 test did not pass\n");
    }

    // Decode Region 2 (bytes 98-113)
    DecodeData(data + 98, 16, algorithm_version, key_index);
    uint8_t region2_crc = CalculateCRC(data + 98, 120);  // 120 bits = 15 bytes
    if (region2_crc != data[113]) {
        printf("Warning: CRC mismatch in Region 2. Calculated: %d, Stored: %d\n", region2_crc, data[113]);
    }
    if (data[108] != 1) {
        printf("Warning: PT2 test did not pass\n");
    }

    // Decode Region 3 (bytes 114-249)
    DecodeData(data + 114, 136, algorithm_version, key_index);
    uint8_t region3_crc = CalculateCRC(data + 114, 1080);  // 1080 bits = 135 bytes
    if (region3_crc != data[249]) {
        printf("Warning: CRC mismatch in Region 3. Calculated: %d, Stored: %d\n", region3_crc, data[249]);
    }
    if (data[247] != 1) {
        printf("Warning: Sweep test did not pass\n");
    }
}

static void encode_eeprom_v4(uint8_t *data, size_t dataSize) {
    uint8_t algorithm_version = data[1] >> 4;
    uint8_t key_index = data[1] & 0xF;

    // Calculate and set CRC for Region 1
    data[97] = CalculateCRC(data, 776);
    // Encode Region 1 (bytes 2-97)
    EncodeData(data + 2, 96, algorithm_version, key_index);

    // Calculate and set CRC for Region 2
    data[113] = CalculateCRC(data + 98, 120);
    // Encode Region 2 (bytes 98-113)
    EncodeData(data + 98, 16, algorithm_version, key_index);
}

static void encode_eeprom_v5(uint8_t *data, size_t dataSize) {
    uint8_t algorithm_version = data[1] >> 4;
    uint8_t key_index = data[1] & 0xF;

    // Calculate and set CRC for Region 1
    data[97] = CalculateCRC(data, 776);
    // Encode Region 1 (bytes 2-97)
    EncodeData(data + 2, 96, algorithm_version, key_index);

    // Calculate and set CRC for Region 2
    data[113] = CalculateCRC(data + 98, 120);
    // Encode Region 2 (bytes 98-113)
    EncodeData(data + 98, 16, algorithm_version, key_index);

    // Calculate and set CRC for Region 3
    data[249] = CalculateCRC(data + 114, 1080);
    // Encode Region 3 (bytes 114-249)
    EncodeData(data + 114, 136, algorithm_version, key_index);
}

static void decode_and_print_eeprom(uint8_t *data, size_t dataSize)
{
    uint8_t eeprom_version = data[0];
    printf("EEPROM Version: %d\n", eeprom_version);

    switch(eeprom_version) {
    case 4:
        decode_eeprom_v4(data, EEPROM_SIZE);
        break;
    case 5:
        decode_eeprom_v5(data, EEPROM_SIZE);
        break;
    default:
        printf("Unsupported EEPROM version: %d\n", eeprom_version);
        return;
    }

    EEPROMStructure eeprom;
    eeprom_from_bytes(&eeprom, data);
    print_eeprom_structure(&eeprom);
}

static void trim(char *str)
{
    char *end;
    while(isspace((unsigned char)*str)) str++;
    if(*str == 0) return;
    end = str + strlen(str) - 1;
    while(end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
}

static void edit_eeprom(EEPROMStructure *eeprom) {
    int choice;
    char buffer[256];

    while (1) {
        printf("\nEEPROM Edit Menu:\n");
        printf("1. Edit EEPROM Version\n");
        printf("2. Edit Algorithm and Key Version\n");
        printf("3. Edit Board SN\n");
        printf("4. Edit Chip Die\n");
        printf("5. Edit Chip Marking\n");
        printf("6. Edit Chip Bin\n");
        printf("7. Edit FT Version\n");
        printf("8. Edit PCB Version\n");
        printf("9. Edit BOM Version\n");
        printf("10. Edit ASIC Sensor Type\n");
        printf("11. Edit ASIC Sensor Addresses\n");
        printf("12. Edit PIC Sensor Type\n");
        printf("13. Edit PIC Sensor Address\n");
        printf("14. Edit Chip Tech\n");
        printf("15. Edit Board Name\n");
        printf("16. Edit Factory Job\n");
        printf("17. Edit PT1 Result\n");
        printf("18. Edit PT1 Count\n");
        printf("19. Edit Voltage\n");
        printf("20. Edit Frequency\n");
        printf("21. Edit Nonce Rate\n");
        printf("22. Edit PCB Temp In\n");
        printf("23. Edit PCB Temp Out\n");
        printf("24. Edit Test Version\n");
        printf("25. Edit Test Standard\n");
        printf("26. Edit PT2 Result\n");
        printf("27. Edit PT2 Count\n");
        printf("28. Edit Sweep Hashrate\n");
        printf("29. Edit Sweep Data\n");
        printf("30. Edit Sweep Result\n");
        printf("31. Print current EEPROM structure\n");
        printf("32. Finish Editing\n");
        printf("Enter your choice: ");
        scanf("%d", &choice);
        getchar();  // Consume newline

        switch(choice) {
        case 1:
            printf("Enter new EEPROM Version: ");
            scanf("%hhu", &eeprom->eeprom_version);
            break;
        case 2:
            printf("Enter new Algorithm and Key Version: ");
            scanf("%hhu", &eeprom->algorithm_and_key_version);
            break;
        case 3:
            printf("Enter new Board SN: ");
            fgets(buffer, sizeof(buffer), stdin);
            trim(buffer);
            strncpy(eeprom->board_sn, buffer, sizeof(eeprom->board_sn) - 1);
            break;
        case 4:
            printf("Enter new Chip Die: ");
            fgets(buffer, sizeof(buffer), stdin);
            trim(buffer);
            strncpy(eeprom->chip_die, buffer, sizeof(eeprom->chip_die) - 1);
            break;
        case 5:
            printf("Enter new Chip Marking: ");
            fgets(buffer, sizeof(buffer), stdin);
            trim(buffer);
            strncpy(eeprom->chip_marking, buffer, sizeof(eeprom->chip_marking) - 1);
            break;
        case 6:
            printf("Enter new Chip Bin: ");
            scanf("%hhu", &eeprom->chip_bin);
            break;
        case 7:
            printf("Enter new FT Version: ");
            fgets(buffer, sizeof(buffer), stdin);
            trim(buffer);
            strncpy(eeprom->ft_version, buffer, sizeof(eeprom->ft_version) - 1);
            break;
        case 8:
            printf("Enter new PCB Version: ");
            scanf("%hu", &eeprom->pcb_version);
            break;
        case 9:
            printf("Enter new BOM Version: ");
            scanf("%hu", &eeprom->bom_version);
            break;
        case 10:
            printf("Enter new ASIC Sensor Type: ");
            scanf("%hhu", &eeprom->asic_sensor_type);
            break;
        case 11:
            printf("Enter new ASIC Sensor Addresses (4 bytes, space-separated): ");
            for (int i = 0; i < 4; i++) {
                scanf("%hhu", &eeprom->asic_sensor_addr[i]);
            }
            break;
        case 12:
            printf("Enter new PIC Sensor Type: ");
            scanf("%hhu", &eeprom->pic_sensor_type);
            break;
        case 13:
            printf("Enter new PIC Sensor Address: ");
            scanf("%hhu", &eeprom->pic_sensor_addr);
            break;
        case 14:
            printf("Enter new Chip Tech: ");
            fgets(buffer, sizeof(buffer), stdin);
            trim(buffer);
            strncpy(eeprom->chip_tech, buffer, sizeof(eeprom->chip_tech) - 1);
            break;
        case 15:
            printf("Enter new Board Name: ");
            fgets(buffer, sizeof(buffer), stdin);
            trim(buffer);
            strncpy(eeprom->board_name, buffer, sizeof(eeprom->board_name) - 1);
            break;
        case 16:
            printf("Enter new Factory Job: ");
            fgets(buffer, sizeof(buffer), stdin);
            trim(buffer);
            strncpy(eeprom->factory_job, buffer, sizeof(eeprom->factory_job) - 1);
            break;
        case 17:
            printf("Enter new PT1 Result: ");
            scanf("%hhu", &eeprom->pt1_result);
            break;
        case 18:
            printf("Enter new PT1 Count: ");
            scanf("%hhu", &eeprom->pt1_count);
            break;
        case 19:
            printf("Enter new Voltage: ");
            scanf("%hu", &eeprom->voltage);
            break;
        case 20:
            printf("Enter new Frequency: ");
            scanf("%hu", &eeprom->frequency);
            break;
        case 21:
            printf("Enter new Nonce Rate: ");
            scanf("%hu", &eeprom->nonce_rate);
            break;
        case 22:
            printf("Enter new PCB Temp In: ");
            scanf("%hhd", &eeprom->pcb_temp_in);
            break;
        case 23:
            printf("Enter new PCB Temp Out: ");
            scanf("%hhd", &eeprom->pcb_temp_out);
            break;
        case 24:
            printf("Enter new Test Version: ");
            scanf("%hhu", &eeprom->test_version);
            break;
        case 25:
            printf("Enter new Test Standard: ");
            scanf("%hhu", &eeprom->test_standard);
            break;
        case 26:
            printf("Enter new PT2 Result: ");
            scanf("%hhu", &eeprom->pt2_result);
            break;
        case 27:
            printf("Enter new PT2 Count: ");
            scanf("%hhu", &eeprom->pt2_count);
            break;
        case 28:
            printf("Enter new Sweep Hashrate: ");
            scanf("%hu", &eeprom->sweep_hashrate);
            break;
        case 29:
            printf("Enter new Sweep Data (32 uint32_t values, space-separated): ");
            for (int i = 0; i < 32; i++) {
                scanf("%u", &eeprom->sweep_data[i]);
            }
            break;
        case 30:
            printf("Enter new Sweep Result: ");
            scanf("%hhu", &eeprom->sweep_result);
            break;
        case 31:
            print_eeprom_structure(eeprom);
            break;
        case 32:
            return;
        default:
            printf("Invalid choice. Please try again.\n");
        }
        getchar();  // Consume any remaining newline
    }
}

static void encode_and_save_eeprom(const char *filename, EEPROMStructure *eeprom) {
    uint8_t data[EEPROM_SIZE];
    eeprom_to_bytes(eeprom, data);

    switch(eeprom->eeprom_version) {
    case 4:
        encode_eeprom_v4(data, EEPROM_SIZE);
        break;
    case 5:
        encode_eeprom_v5(data, EEPROM_SIZE);
        break;
    default:
        printf("Unsupported EEPROM version: %d\n", eeprom->eeprom_version);
        return;
    }

    if (write_file(filename, data, EEPROM_SIZE)) {
        printf("EEPROM data successfully encoded and saved to %s\n", filename);
    } else {
        printf("Failed to save encoded EEPROM data to %s\n", filename);
    }
}

int main(void) {
    char input_filename[MAX_FILENAME];
    char output_filename[MAX_FILENAME];
    uint8_t data[EEPROM_SIZE];
    EEPROMStructure eeprom;

    while (1) {
        printf("\nEEPROM Tool Menu:\n");
        printf("1. Decode and Print EEPROM\n");
        printf("2. Decode, Edit, and Encode EEPROM\n");
        printf("3. Exit\n");
        printf("Enter your choice: ");

        int choice;
        scanf("%d", &choice);

        switch (choice) {
        case 1:
            printf("Enter input filename: ");
            scanf("%255s", input_filename);
            if (read_file(input_filename, data, EEPROM_SIZE)) {
                decode_and_print_eeprom(data, EEPROM_SIZE);
            } else {
                printf("Failed to read input file.\n");
            }
            break;
        case 2:
            printf("Enter input filename: ");
            scanf("%255s", input_filename);
            if (read_file(input_filename, data, EEPROM_SIZE)) {
                decode_and_print_eeprom(data, EEPROM_SIZE);
                eeprom_from_bytes(&eeprom, data);
                edit_eeprom(&eeprom);
                printf("Enter output filename: ");
                scanf("%255s", output_filename);
                encode_and_save_eeprom(output_filename, &eeprom);
            } else {
                printf("Failed to read input file.\n");
            }
            break;
        case 3:
            printf("Exiting program.\n");
            return 0;
        default:
            printf("Invalid choice. Please try again.\n");
        }
    }

    return 0;
}

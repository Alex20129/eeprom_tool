#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "eeprom_defs.h"
#include "eeprom_structure.h"
#include "eeprom_ops.h"
#include "ui.h"

#ifdef HAVE_I2C_SUPPORT
#include "i2c_eeprom.h"
#endif

#define MAX_FILENAME 256

static int read_eeprom_file(const char *filename, uint8_t *buffer)
{
	FILE *file = fopen(filename, "rb");
	if (!file)
	{
		printf("Error: Cannot open file %s\n", filename);
		return -1;
	}

	fseek(file, 0, SEEK_END);
	long file_size = ftell(file);
	fseek(file, 0, SEEK_SET);

	if (file_size <= 0 || file_size > EEPROM_SIZE)
	{
		printf("Error: Invalid file size: %ld bytes (expected 1-%d)\n",
			   file_size, EEPROM_SIZE);
		fclose(file);
		return -4;
	}

	size_t read_size = fread(buffer, 1, file_size, file);
	fclose(file);

	if (read_size != (size_t)file_size)
	{
		printf("Error: Failed to read file completely\n");
		return -2;
	}

	printf("Read %zu bytes from %s\n", read_size, filename);
	return 0;
}

static int write_eeprom_file(const char *filename, const uint8_t *buffer, size_t size)
{
	FILE *file = fopen(filename, "wb");
	if (!file)
	{
		printf("Error: Cannot open file %s for writing\n", filename);
		return -1;
	}

	size_t written_size = fwrite(buffer, 1, size, file);
	fclose(file);

	if (written_size != size)
	{
		printf("Error: Failed to write all data. Wrote %zu of %zu bytes\n",
			   written_size, size);
		return -3;
	}

	printf("Successfully wrote %zu bytes to %s\n", size, filename);
	return 0;
}

// ═══════════════════════════════════════════════════════════════
// Функции для работы с EEPROM
// ═══════════════════════════════════════════════════════════════

static void decode_and_print_eeprom(uint8_t *data)
{
	EEPROMVersion version = eeprom_detect_version(data);

	// Decode data
	if (eeprom_decode(data, EEPROM_SIZE, version) != EEPROM_SUCCESS)
	{
		ui_print_error("Failed to decode EEPROM");
		return;
	}

	// Parse and print structure
	switch(version)
	{
		case EEPROM_VERSION_V1:
		{
			EEPROMStructure_v1 eeprom_v1;
			eeprom_v1_parse(&eeprom_v1, data);
			ui_print_eeprom(&eeprom_v1, version);
			break;
		}
		case EEPROM_VERSION_V4:
		case EEPROM_VERSION_V5:
		case EEPROM_VERSION_V6:
		{
			EEPROMStructure eeprom;
			eeprom_from_bytes(&eeprom, data);
			ui_print_eeprom(&eeprom, version);
			break;
		}
		case EEPROM_VERSION_V17:
		{
			EEPROMStructure_v17 eeprom_v17;
			eeprom_v17_parse(&eeprom_v17, data);
			ui_print_eeprom(&eeprom_v17, version);
			break;
		}
		default:
			ui_print_error("Unsupported EEPROM version: %d", version);
			break;
	}
}

static void encode_and_save_eeprom(const char *filename, EEPROMStructure *eeprom)
{
	uint8_t data[EEPROM_SIZE];
	eeprom_to_bytes(eeprom, data);

	if (eeprom_encode(data, EEPROM_SIZE, (EEPROMVersion)eeprom->eeprom_version) != EEPROM_SUCCESS)
	{
		printf("Error: Failed to encode EEPROM\n");
		return;
	}

	if (write_eeprom_file(filename, data, EEPROM_SIZE) == 0)
	{
		printf("EEPROM data successfully encoded and saved to %s\n", filename);
	}
}

static void encode_and_save_eeprom_v1(const char *filename, EEPROMStructure_v1 *eeprom)
{
	uint8_t data[EEPROM_SIZE];
	memset(data, 0xFF, EEPROM_SIZE);

	eeprom_v1_serialize(eeprom, data);

	if (eeprom_encode(data, EEPROM_SIZE, EEPROM_VERSION_V1) != EEPROM_SUCCESS)
	{
		printf("Error: Failed to encode EEPROM v1\n");
		return;
	}

	size_t size = eeprom_get_used_size(EEPROM_VERSION_V1);
	if (write_eeprom_file(filename, data, size) == 0)
	{
		printf("EEPROM v1 data successfully encoded and saved to %s\n", filename);
	}
}

static void encode_and_save_eeprom_v17(const char *filename, EEPROMStructure_v17 *eeprom)
{
	uint8_t data[EEPROM_SIZE];
	memset(data, 0xFF, EEPROM_SIZE);

	eeprom_v17_serialize(eeprom, data);

	if (eeprom_encode(data, EEPROM_SIZE, EEPROM_VERSION_V17) != EEPROM_SUCCESS)
	{
		printf("Error: Failed to encode EEPROM v17\n");
		return;
	}

	size_t size = eeprom_get_used_size(EEPROM_VERSION_V17);
	if (write_eeprom_file(filename, data, size) == 0)
	{
		printf("EEPROM v17 data successfully encoded and saved to %s\n", filename);
	}
}

// ═══════════════════════════════════════════════════════════════
// Главное меню
// ═══════════════════════════════════════════════════════════════
#include <locale.h>
int main(int argc, char *argv[])
{
	setlocale(LC_ALL, "en_US.UTF-8");

	char input_filename[MAX_FILENAME];
	char output_filename[MAX_FILENAME];
	uint8_t data[EEPROM_SIZE];

	while (1)
	{
		printf("\nEEPROM Tool Menu:\n");
		printf("1. Decode and Print EEPROM from file\n");
		printf("2. Decode, Edit, and Encode EEPROM from file\n");
#ifdef HAVE_I2C_SUPPORT
		printf("3. Read EEPROM from I2C board\n");
		printf("4. Exit\n");
#else
		printf("3. Exit\n");
#endif
		printf("Enter your choice: ");

		int choice;
		scanf("%d", &choice);

		switch (choice)
		{
		case 1:
			printf("Enter input filename: ");
			scanf("%255s", input_filename);
			memset(data, 0xFF, EEPROM_SIZE);
			if (read_eeprom_file(input_filename, data) == 0)
			{
				decode_and_print_eeprom(data);
			}
			break;

		case 2:
			printf("Enter input filename: ");
			scanf("%255s", input_filename);
			memset(data, 0xFF, EEPROM_SIZE);
			if (read_eeprom_file(input_filename, data) == 0)
			{
				EEPROMVersion version = eeprom_detect_version(data);

				if (eeprom_decode(data, EEPROM_SIZE, version) != EEPROM_SUCCESS)
				{
					ui_print_error("Failed to decode EEPROM");
					break;
				}

				if (version == EEPROM_VERSION_V1)
				{
					EEPROMStructure_v1 eeprom_v1;
					eeprom_v1_parse(&eeprom_v1, data);

					if (eeprom_edit_interactive(&eeprom_v1, version) == EEPROM_SUCCESS)
					{
						printf("Enter output filename: ");
						scanf("%255s", output_filename);
						encode_and_save_eeprom_v1(output_filename, &eeprom_v1);
					}
				}
				else if (version >= EEPROM_VERSION_V4 && version <= EEPROM_VERSION_V6)
				{
					EEPROMStructure eeprom;
					eeprom_from_bytes(&eeprom, data);

					if (eeprom_edit_interactive(&eeprom, version) == EEPROM_SUCCESS)
					{
						printf("Enter output filename: ");
						scanf("%255s", output_filename);
						encode_and_save_eeprom(output_filename, &eeprom);
					}
				}
				else if (version == EEPROM_VERSION_V17)
				{
					EEPROMStructure_v17 eeprom_v17;
					eeprom_v17_parse(&eeprom_v17, data);

					if (eeprom_edit_interactive(&eeprom_v17, version) == EEPROM_SUCCESS)
					{
						printf("Enter output filename: ");
						scanf("%255s", output_filename);
						encode_and_save_eeprom_v17(output_filename, &eeprom_v17);
					}
				}
				else
				{
					ui_print_error("Unsupported EEPROM version for editing");
				}
			}
			break;

#ifdef HAVE_I2C_SUPPORT
		case 3:
		{
			char i2c_device[MAX_FILENAME];
			int i2c_addr;

			printf("Enter I2C device path (e.g., /dev/i2c-0): ");
			scanf("%255s", i2c_device);

			printf("Enter I2C device address (0x50-0x53, default 0x50): ");
			if (scanf("%i", &i2c_addr) != 1)
			{
				i2c_addr = 0x50;
			}

			int fd = iic_open(i2c_device, NULL);
			if (fd < 0)
			{
				ui_print_error("Failed to open I2C device: %s", i2c_device);
				break;
			}

			memset(data, 0xFF, EEPROM_SIZE);
			int result = iic_eeprom_load(fd, (uint8_t)i2c_addr, 0, data, EEPROM_SIZE);
			iic_close(fd);

			if (result < 0)
			{
				ui_print_error("Failed to read EEPROM from I2C");
				break;
			}

			ui_print_success("Successfully read %d bytes from I2C device", EEPROM_SIZE);

			// Decode and print
			decode_and_print_eeprom(data);

			// Ask if user wants to save to file
			printf("\nSave to file? (y/n): ");
			char save_choice;
			scanf(" %c", &save_choice);
			if (save_choice == 'y' || save_choice == 'Y')
			{
				printf("Enter output filename: ");
				scanf("%255s", output_filename);
				if (write_eeprom_file(output_filename, data, EEPROM_SIZE) == 0)
				{
					ui_print_success("Data saved to %s", output_filename);
				}
			}
			break;
		}

		case 4:
			printf("Exiting program.\n");
			return 0;
#else
		case 3:
			printf("Exiting program.\n");
			return 0;
#endif

		default:
			printf("Invalid choice. Please try again.\n");
		}
	}

	return 0;
}

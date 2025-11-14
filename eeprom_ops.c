#include "eeprom_ops.h"
#include "crypto.h"
#include <stdio.h>
#include <string.h>

// ═══════════════════════════════════════════════════════════════
// Generic Region Processing
// ═══════════════════════════════════════════════════════════════

static void process_region_decode(uint8_t *data,
								   const RegionMeta *region,
								   uint8_t algorithm,
								   uint8_t key_index,
								   EEPROMVersion version)
{
	decode_data(data + region->data_start,
			   region->data_size,
			   algorithm, key_index, version);

	uint8_t calculated_crc = calculate_crc(data, region->crc_bits);
	if (calculated_crc != data[region->crc_pos])
	{
		printf("Warning: CRC mismatch in %s. Calculated: 0x%02X, Stored: 0x%02X\n",
			  region->name, calculated_crc, data[region->crc_pos]);
	}

	if (region->test_result_pos >= 0 && region->test_name)
	{
		if (data[region->test_result_pos] != 1)
		{
			printf("Warning: %s test did not pass (result = %d)\n",
				  region->test_name, data[region->test_result_pos]);
		}
	}
}

static void process_region_encode(uint8_t *data,
								   const RegionMeta *region,
								   uint8_t algorithm,
								   uint8_t key_index,
								   EEPROMVersion version)
{
	data[region->crc_pos] = calculate_crc(data, region->crc_bits);

	encode_data(data + region->data_start,
			   region->data_size,
			   algorithm, key_index, version);
}

int eeprom_decode(uint8_t *data, size_t size, EEPROMVersion version)
{
	if (size != EEPROM_SIZE)
	{
		printf("Error: Invalid buffer size %zu, expected %d\n", size, EEPROM_SIZE);
		return EEPROM_ERROR_UNKNOWN;
	}

	if (version == EEPROM_VERSION_UNKNOWN)
	{
		version = eeprom_detect_version(data);
		if (version == EEPROM_VERSION_UNKNOWN)
		{
			printf("Error: Unknown EEPROM version (byte 0 = 0x%02X)\n", data[0]);
			return EEPROM_ERROR_VERSION;
		}
	}

	printf("EEPROM Version: %d (0x%02X)\n", version, data[0]);

	// ═══════════════════════════════════════════════════════════════
	// EEPROM v1 (AES-256-CBC)
	// ═══════════════════════════════════════════════════════════════
	if (version == EEPROM_VERSION_V1)
	{
		uint32_t encryption_key = EEPROM_V1_KEY_PRODUCTION;

		if (decode_data_v1(data + EEPROM_V1_PT1_START,
						   EEPROM_V1_PT1_SIZE,
						   encryption_key) != 0)
		{
			printf("Error: Failed to decrypt PT1 block\n");
			return EEPROM_ERROR_UNKNOWN;
		}

		uint8_t pt1_crc_calc = calculate_crc8_v1(data + EEPROM_V1_PT1_START,
												  EEPROM_V1_PT1_CRC_BYTES);
		if (pt1_crc_calc != data[EEPROM_V1_PT1_CRC_POS])
		{
			printf("Warning: PT1 CRC mismatch. Calculated: 0x%02X, Stored: 0x%02X\n",
				   pt1_crc_calc, data[EEPROM_V1_PT1_CRC_POS]);
		}

		if (decode_data_v1(data + EEPROM_V1_PT2_START,
						   EEPROM_V1_PT2_SIZE,
						   encryption_key) != 0)
		{
			printf("Error: Failed to decrypt PT2 block\n");
			return EEPROM_ERROR_UNKNOWN;
		}

		uint8_t pt2_crc_calc = calculate_crc8_v1(data + EEPROM_V1_PT2_START,
												  EEPROM_V1_PT2_CRC_BYTES);
		if (pt2_crc_calc != data[EEPROM_V1_PT2_CRC_POS])
		{
			printf("Warning: PT2 CRC mismatch. Calculated: 0x%02X, Stored: 0x%02X\n",
				   pt2_crc_calc, data[EEPROM_V1_PT2_CRC_POS]);
		}

		if (decode_data_v1(data + EEPROM_V1_SWEEP_START,
						   EEPROM_V1_SWEEP_SIZE,
						   encryption_key) != 0)
		{
			printf("Error: Failed to decrypt SWEEP block\n");
			return EEPROM_ERROR_UNKNOWN;
		}

		uint8_t sweep_crc_calc = calculate_crc8_v1(data + EEPROM_V1_SWEEP_START,
													EEPROM_V1_SWEEP_CRC_BYTES);
		if (sweep_crc_calc != data[EEPROM_V1_SWEEP_CRC_POS])
		{
			printf("Warning: SWEEP CRC mismatch. Calculated: 0x%02X, Stored: 0x%02X\n",
				   sweep_crc_calc, data[EEPROM_V1_SWEEP_CRC_POS]);
		}

		return EEPROM_SUCCESS;
	}

	// ═══════════════════════════════════════════════════════════════
	// EEPROM v4/v5/v6/v17 - Generic region processing (XXTEA/XOR)
	// ═══════════════════════════════════════════════════════════════

	const EEPROMLayout *layout = eeprom_get_layout(version);
	if (!layout)
	{
		printf("Error: No layout found for EEPROM version %d\n", version);
		return EEPROM_ERROR_VERSION;
	}

	uint8_t algorithm = layout->algorithm;
	uint8_t key_index = layout->key_index;

	if (version >= EEPROM_VERSION_V4 && version <= EEPROM_VERSION_V6)
	{
		algorithm = data[1] >> 4;
		key_index = data[1] & 0xF;
	}

	for (size_t i = 0; i < layout->region_count; i++)
	{
		process_region_decode(data, &layout->regions[i],
							 algorithm, key_index, version);
	}

	return EEPROM_SUCCESS;
}

int eeprom_encode(uint8_t *data, size_t size, EEPROMVersion version)
{
	if (size != EEPROM_SIZE)
	{
		printf("Error: Invalid buffer size %zu, expected %d\n", size, EEPROM_SIZE);
		return EEPROM_ERROR_UNKNOWN;
	}

	if (version == EEPROM_VERSION_UNKNOWN)
	{
		version = eeprom_detect_version(data);
		if (version == EEPROM_VERSION_UNKNOWN)
		{
			printf("Error: Unknown EEPROM version (byte 0 = 0x%02X)\n", data[0]);
			return EEPROM_ERROR_VERSION;
		}
	}

	// ═══════════════════════════════════════════════════════════════
	// EEPROM v1 (AES-256-CBC)
	// ═══════════════════════════════════════════════════════════════
	if (version == EEPROM_VERSION_V1)
	{
		uint32_t encryption_key = EEPROM_V1_KEY_PRODUCTION;

		data[EEPROM_V1_PT1_CRC_POS] = calculate_crc8_v1(data + EEPROM_V1_PT1_START,
														 EEPROM_V1_PT1_CRC_BYTES);

		if (encode_data_v1(data + EEPROM_V1_PT1_START,
						   EEPROM_V1_PT1_SIZE,
						   encryption_key) != 0)
		{
			printf("Error: Failed to encrypt PT1 block\n");
			return EEPROM_ERROR_UNKNOWN;
		}

		data[EEPROM_V1_PT2_CRC_POS] = calculate_crc8_v1(data + EEPROM_V1_PT2_START,
														 EEPROM_V1_PT2_CRC_BYTES);

		if (encode_data_v1(data + EEPROM_V1_PT2_START,
						   EEPROM_V1_PT2_SIZE,
						   encryption_key) != 0)
		{
			printf("Error: Failed to encrypt PT2 block\n");
			return EEPROM_ERROR_UNKNOWN;
		}

		data[EEPROM_V1_SWEEP_CRC_POS] = calculate_crc8_v1(data + EEPROM_V1_SWEEP_START,
														   EEPROM_V1_SWEEP_CRC_BYTES);

		if (encode_data_v1(data + EEPROM_V1_SWEEP_START,
						   EEPROM_V1_SWEEP_SIZE,
						   encryption_key) != 0)
		{
			printf("Error: Failed to encrypt SWEEP block\n");
			return EEPROM_ERROR_UNKNOWN;
		}

		return EEPROM_SUCCESS;
	}

	// ═══════════════════════════════════════════════════════════════
	// EEPROM v4/v5/v6/v17 - Generic region processing (XXTEA/XOR)
	// ═══════════════════════════════════════════════════════════════

	const EEPROMLayout *layout = eeprom_get_layout(version);
	if (!layout)
	{
		printf("Error: No layout found for EEPROM version %d\n", version);
		return EEPROM_ERROR_VERSION;
	}

	uint8_t algorithm = layout->algorithm;
	uint8_t key_index = layout->key_index;

	if (version >= EEPROM_VERSION_V4 && version <= EEPROM_VERSION_V6)
	{
		algorithm = data[1] >> 4;
		key_index = data[1] & 0xF;
	}

	for (size_t i = 0; i < layout->region_count; i++)
	{
		process_region_encode(data, &layout->regions[i],
							 algorithm, key_index, version);
	}

	return EEPROM_SUCCESS;
}

// ═══════════════════════════════════════════════════════════════
// Interactive Editing Functions
// ═══════════════════════════════════════════════════════════════

#include "ui.h"

static int edit_field_interactive(void *base, const FieldMetadata *field)
{
	uint8_t *ptr = (uint8_t*)base + field->offset;

	if (field->read_only)
	{
		ui_print_warning("Field '%s' is read-only", field->name);
		return EEPROM_SUCCESS;
	}

	printf("\n");
	ui_print_info("Editing: %s", field->name);
	printf("Current value: ");
	ui_print_field(base, field);

	switch (field->type)
	{
		case FIELD_TYPE_UINT8:
		case FIELD_TYPE_HEX8:
		{
			uint8_t value;
			if (ui_input_uint8("New value", &value, field->min_value, field->max_value))
			{
				*(uint8_t*)ptr = value;
				ui_print_success("Updated");
			}
			break;
		}

		case FIELD_TYPE_UINT16:
		case FIELD_TYPE_HEX16:
		case FIELD_TYPE_VOLTAGE:
		case FIELD_TYPE_HASHRATE:
		{
			uint16_t value;
			if (ui_input_uint16("New value", &value, field->min_value, field->max_value))
			{
				*(uint16_t*)ptr = value;
				ui_print_success("Updated");
			}
			break;
		}

		case FIELD_TYPE_INT8:
		{
			int8_t value;
			if (ui_input_int8("New value", &value, field->min_value, field->max_value))
			{
				*(int8_t*)ptr = value;
				ui_print_success("Updated");
			}
			break;
		}

		case FIELD_TYPE_STRING:
		{
			char buffer[256];
			if (ui_input_string("New value", buffer, sizeof(buffer)))
			{
				strncpy((char*)ptr, buffer, field->size);
				((char*)ptr)[field->size - 1] = '\0';
				ui_print_success("Updated");
			}
			break;
		}

		default:
			ui_print_error("Editing not supported for this field type");
			return EEPROM_ERROR_UNKNOWN;
	}

	return EEPROM_SUCCESS;
}

int eeprom_edit_interactive(void *eeprom_struct, EEPROMVersion version)
{
	size_t field_count;
	const FieldMetadata *fields = eeprom_get_fields(version, &field_count);

	if (!fields || field_count == 0)
	{
		ui_print_error("No field metadata for EEPROM version %d", version);
		return EEPROM_ERROR_VERSION;
	}

	while (1)
	{
		ui_print_eeprom(eeprom_struct, version);

		printf("\n" TERM_BOLD "Edit Menu:" TERM_RESET "\n");
		printf("Select field to edit (1-%zu), or 0 to finish:\n", field_count);

		const char *current_category = NULL;
		for (size_t i = 0; i < field_count; i++)
		{
			if (current_category == NULL || strcmp(current_category, fields[i].category) != 0)
			{
				printf("\n" TERM_BOLD TERM_CYAN "  %s:" TERM_RESET "\n", fields[i].category);
				current_category = fields[i].category;
			}
			printf("    [%2zu] %s", i + 1, fields[i].name);
			if (fields[i].read_only)
			{
				printf(TERM_DIM " (read-only)" TERM_RESET);
			}
			printf("\n");
		}

		printf("\n    [ 0] " TERM_BOLD TERM_GREEN "Finish editing" TERM_RESET "\n");

		printf("\nChoice: ");
		int choice;
		if (scanf("%d", &choice) != 1)
		{
			while (getchar() != '\n');
			ui_print_error("Invalid input");
			continue;
		}
		getchar();

		if (choice == 0)
		{
			break;
		}

		if (choice < 1 || choice > (int)field_count)
		{
			ui_print_error("Invalid choice (1-%zu)", field_count);
			continue;
		}

		const FieldMetadata *field = &fields[choice - 1];
		edit_field_interactive(eeprom_struct, field);
	}

	ui_print_success("Editing complete");
	return EEPROM_SUCCESS;
}

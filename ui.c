#include "ui.h"
#include "eeprom_structure.h"
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>

// ═══════════════════════════════════════════════════════════════
// Formatted Output Functions
// ═══════════════════════════════════════════════════════════════

void ui_print_success(const char *format, ...)
{
	va_list args;
	va_start(args, format);
	printf(TERM_GREEN "✓ " TERM_RESET);
	vprintf(format, args);
	printf("\n");
	va_end(args);
}

void ui_print_error(const char *format, ...)
{
	va_list args;
	va_start(args, format);
	printf(TERM_RED "✗ Error: " TERM_RESET);
	vprintf(format, args);
	printf("\n");
	va_end(args);
}

void ui_print_warning(const char *format, ...)
{
	va_list args;
	va_start(args, format);
	printf(TERM_YELLOW "⚠ Warning: " TERM_RESET);
	vprintf(format, args);
	printf("\n");
	va_end(args);
}

void ui_print_info(const char *format, ...)
{
	va_list args;
	va_start(args, format);
	printf(TERM_CYAN "ℹ " TERM_RESET);
	vprintf(format, args);
	printf("\n");
	va_end(args);
}

void ui_print_header(const char *title)
{
	printf("\n");
	printf(TERM_BOLD TERM_CYAN "%s" TERM_RESET "\n", title);
	printf(TERM_DIM "════════════════════════════════════════════════════════════════\n" TERM_RESET);
}

void ui_print_separator(void)
{
	printf(TERM_DIM "────────────────────────────────────────────────────────────────\n" TERM_RESET);
}

void ui_print_category_header(const char *category)
{
	printf("\n");
	printf(TERM_BOLD TERM_BLUE "── %s " TERM_RESET, category);
	printf(TERM_DIM "────────────────────────────────────────────────────────\n" TERM_RESET);
}

// ═══════════════════════════════════════════════════════════════
// Hex Dump Functions
// ═══════════════════════════════════════════════════════════════

static void ui_print_hex_dump(const uint8_t *data, size_t size)
{
	for (size_t i = 0; i < size; i += 16)
	{
		printf("  %04zX: ", i);

		for (size_t j = 0; j < 16; j++)
		{
			if (i + j < size)
			{
				printf("%02X ", data[i + j]);
			}
			else
			{
				printf("   ");
			}

			if (j == 7)
			{
				printf(" ");
			}
		}

		printf("\n");
	}
}

// ═══════════════════════════════════════════════════════════════
// Input Functions with Validation
// ═══════════════════════════════════════════════════════════════

bool ui_input_uint8(const char *prompt, uint8_t *value, uint8_t min, uint8_t max)
{
	int input;
	printf("%s [%u-%u]: ", prompt, min, max);

	if (scanf("%d", &input) != 1)
	{
		while (getchar() != '\n');  // Clear input buffer
		ui_print_error("Invalid input");
		return false;
	}

	if (input < min || input > max)
	{
		ui_print_error("Value out of range (%u-%u)", min, max);
		return false;
	}

	*value = (uint8_t)input;
	return true;
}

bool ui_input_uint16(const char *prompt, uint16_t *value, uint16_t min, uint16_t max)
{
	int input;
	printf("%s [%u-%u]: ", prompt, min, max);

	if (scanf("%d", &input) != 1)
	{
		while (getchar() != '\n');
		ui_print_error("Invalid input");
		return false;
	}

	if (input < min || input > max)
	{
		ui_print_error("Value out of range (%u-%u)", min, max);
		return false;
	}

	*value = (uint16_t)input;
	return true;
}

bool ui_input_int8(const char *prompt, int8_t *value, int8_t min, int8_t max)
{
	int input;
	printf("%s [%d-%d]: ", prompt, min, max);

	if (scanf("%d", &input) != 1)
	{
		while (getchar() != '\n');
		ui_print_error("Invalid input");
		return false;
	}

	if (input < min || input > max)
	{
		ui_print_error("Value out of range (%d-%d)", min, max);
		return false;
	}

	*value = (int8_t)input;
	return true;
}

bool ui_input_string(const char *prompt, char *buffer, size_t maxlen)
{
	printf("%s (max %zu chars): ", prompt, maxlen - 1);

	if (fgets(buffer, maxlen, stdin) == NULL)
	{
		ui_print_error("Failed to read input");
		return false;
	}

	size_t len = strlen(buffer);
	if (len > 0 && buffer[len-1] == '\n')
	{
		buffer[len-1] = '\0';
	}

	return true;
}

// ═══════════════════════════════════════════════════════════════
// EEPROM Display Functions
// ═══════════════════════════════════════════════════════════════

void ui_print_field(const void *base, const FieldMetadata *field)
{
	const uint8_t *ptr = (const uint8_t*)base + field->offset;
	char value_buf[256];
	value_buf[0] = '\0';

	switch (field->type)
	{
		case FIELD_TYPE_UINT8:
		{
			uint8_t value = *(const uint8_t*)ptr;
			snprintf(value_buf, sizeof(value_buf), field->format, value);
			break;
		}

		case FIELD_TYPE_UINT16:
		{
			uint16_t value = *(const uint16_t*)ptr;
			if (field->unit)
			{
				snprintf(value_buf, sizeof(value_buf), "%u %s", value, field->unit);
			}
			else
			{
				snprintf(value_buf, sizeof(value_buf), "%u", value);
			}
			break;
		}

		case FIELD_TYPE_INT8:
		{
			int8_t value = *(const int8_t*)ptr;
			if (field->unit)
			{
				snprintf(value_buf, sizeof(value_buf), "%d %s", value, field->unit);
			}
			else
			{
				snprintf(value_buf, sizeof(value_buf), "%d", value);
			}
			break;
		}

		case FIELD_TYPE_STRING:
		{
			snprintf(value_buf, sizeof(value_buf), field->format, (const char*)ptr);
			break;
		}

		case FIELD_TYPE_HEX8:
		{
			uint8_t value = *(const uint8_t*)ptr;
			snprintf(value_buf, sizeof(value_buf), "0x%02X", value);
			break;
		}

		case FIELD_TYPE_HEX16:
		{
			uint16_t value = *(const uint16_t*)ptr;
			snprintf(value_buf, sizeof(value_buf), "0x%04X", value);
			break;
		}

		case FIELD_TYPE_VOLTAGE:
		{
			uint16_t value = *(const uint16_t*)ptr;
			snprintf(value_buf, sizeof(value_buf), "%.2f V", value / 100.0f);
			break;
		}

		case FIELD_TYPE_HASHRATE:
		{
			uint16_t value = *(const uint16_t*)ptr;
			snprintf(value_buf, sizeof(value_buf), "%.2f GH/s", value / 100.0f);
			break;
		}

		case FIELD_TYPE_ARRAY_UINT8:
		{
			if (strcmp(field->name, "ASIC Frequencies") == 0)
			{
				const EEPROMStructure *eeprom = (const EEPROMStructure*)base;
				uint16_t freq_base = eeprom->sweep_data.sweep_freq_base;
				uint8_t freq_step = eeprom->sweep_data.sweep_freq_step;
				size_t array_size = field->size;  // 128 bytes for v4/v5/v6
				const uint8_t *array = (const uint8_t*)ptr;

				printf("  " TERM_BOLD "%-27s" TERM_RESET ":", field->name);
				if (field->read_only)
				{
					printf(TERM_DIM " [RO]" TERM_RESET);
				}
				printf("\n");

				// Выводим частоты (каждый байт содержит 2 частоты по 4 бита)
				for (size_t i = 0; i < array_size; i++)
				{
					if (i % 8 == 0)
					{
						printf("    ");
					}

					uint8_t v0 = array[i] >> 4;      // Старшие 4 бита
					uint8_t v1 = array[i] & 0x0F;    // Младшие 4 бита

					uint16_t freq0 = v0 * freq_step + freq_base;
					uint16_t freq1 = v1 * freq_step + freq_base;

					printf(" %4u %4u", freq0, freq1);

					if ((i % 8) == 7)
					{
						printf("\n");
					}
				}

				return;
			}
			else
			{
				const uint8_t *array = (const uint8_t*)ptr;
				int pos = 0;
				pos += snprintf(value_buf + pos, sizeof(value_buf) - pos, "[");
				for (size_t i = 0; i < field->size && i < 16; i++)
				{
					if (i > 0) pos += snprintf(value_buf + pos, sizeof(value_buf) - pos, " ");
					pos += snprintf(value_buf + pos, sizeof(value_buf) - pos, "0x%02X", array[i]);
				}
				if (field->size > 16)
				{
					pos += snprintf(value_buf + pos, sizeof(value_buf) - pos, " ...");
				}
				snprintf(value_buf + pos, sizeof(value_buf) - pos, "]");
			}
			break;
		}

		default:
			snprintf(value_buf, sizeof(value_buf), "<unknown type>");
			break;
	}

	printf("  " TERM_BOLD "%-27s" TERM_RESET ": %s", field->name, value_buf);

	if (field->read_only)
	{
		printf(TERM_DIM " [RO]" TERM_RESET);
	}

	printf("\n");
}

void ui_print_eeprom(const void *eeprom_struct, EEPROMVersion version)
{
	size_t field_count;
	const FieldMetadata *fields = eeprom_get_fields(version, &field_count);

	if (!fields || field_count == 0)
	{
		ui_print_error("No field metadata for EEPROM version %d", version);
		return;
	}

	char title[64];
	if (version == EEPROM_VERSION_V1)
	{
		snprintf(title, sizeof(title), "EEPROM v1 Structure (Antminer S21+ Series)");
	}
	else if (version == EEPROM_VERSION_V17)
	{
		snprintf(title, sizeof(title), "EEPROM v17 Structure (Antminer L Series)");
	}
	else
	{
		snprintf(title, sizeof(title), "EEPROM v%d Structure (Antminer S Series)", version);
	}
	ui_print_header(title);

	const char *current_category = NULL;

	for (size_t i = 0; i < field_count; i++)
	{
		const FieldMetadata *field = &fields[i];

		if (current_category == NULL || strcmp(current_category, field->category) != 0)
		{
			ui_print_category_header(field->category);
			current_category = field->category;
		}

		ui_print_field(eeprom_struct, field);
	}

	// Special handling for EEPROM v1 SWEEP region (raw data)
	if (version == EEPROM_VERSION_V1)
	{
		const EEPROMStructure_v1 *eeprom_v1 = (const EEPROMStructure_v1*)eeprom_struct;

		ui_print_category_header("SWEEP Region (raw data)");
		printf("  " TERM_DIM "Structure unknown - showing decrypted raw bytes\n" TERM_RESET);
		ui_print_hex_dump(eeprom_v1->sweep_data_raw, 144);
	}

	printf("\n");
}

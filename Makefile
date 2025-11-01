CC   ?= gcc
CXX  ?= g++
CFLAGS = -Wall -march=native -O2
LDFLAGS= -s 

SRC = crypto.c eeprom_structure.c main.c

OUTPUT=eeprom_tool
INSTALL=eeprom_tool

.PHONY: all clean

all: $(OUTPUT)

$(OUTPUT): $(SRC:.c=.o)
	$(CC) $(LDFLAGS) -o $(OUTPUT) $^

clean:
	rm -f $(OUTPUT) $(SRC:.c=.o)

install: $(OUTPUT)
	@mkdir -p $(INSTALL)

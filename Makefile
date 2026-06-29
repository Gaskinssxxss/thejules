# Makefile

ARDUINO_CLI ?= arduino-cli

# Cek dengan: arduino-cli board listall esp32
BOARD_FQBN  ?= esp32:esp32:esp32

# Sesuaikan dengan port ESP32 kamu
PORT        ?= /dev/ttyUSB0

SKETCH_DIR  := .
INCLUDE_DIR := $(SKETCH_DIR)/include

.PHONY: all compile upload clean

all: compile

compile:
	$(ARDUINO_CLI) compile --fqbn $(BOARD_FQBN) \
	  --build-property compiler.cpp.extra_flags="-I$(INCLUDE_DIR)" \
	  --build-property compiler.c.extra_flags="-I$(INCLUDE_DIR)" \
	  $(SKETCH_DIR)

upload:
	$(ARDUINO_CLI) upload -p $(PORT) --fqbn $(BOARD_FQBN) $(SKETCH_DIR)

clean:
	rm -rf build */.arduino* .arduino*

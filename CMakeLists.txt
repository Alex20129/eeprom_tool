CMAKE_MINIMUM_REQUIRED(VERSION 3.10)

PROJECT(eeprom_tool)

SET(CMAKE_BUILD_TYPE Debug)

SET(CMAKE_C_FLAGS "-O2 -Wall")

# Find OpenSSL for AES-256-CBC (EEPROM v1 support)
FIND_PACKAGE(OpenSSL REQUIRED)

# Common sources for all platforms
SET(SOURCES
    main.c
    crypto.c
    crypto.h
    eeprom_defs.h
    eeprom_ops.c
    eeprom_ops.h
    eeprom_structure.c
    eeprom_structure.h
    ui.c
    ui.h
)

# Add I2C support only on Linux
IF(UNIX AND NOT APPLE)
    LIST(APPEND SOURCES i2c_eeprom.c i2c_eeprom.h)
    ADD_DEFINITIONS(-DHAVE_I2C_SUPPORT)
ENDIF()

ADD_EXECUTABLE(${PROJECT_NAME} ${SOURCES})

# Link OpenSSL libraries
TARGET_LINK_LIBRARIES(${PROJECT_NAME} OpenSSL::SSL OpenSSL::Crypto)

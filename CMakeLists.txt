CMAKE_MINIMUM_REQUIRED(VERSION 3.0)

PROJECT(eeprom_tool)

SET(CMAKE_BUILD_TYPE Debug)

SET(CMAKE_C_FLAGS "-O0 -Wall")

ADD_EXECUTABLE(${PROJECT_NAME}
    main.c
    crypto.c
    crypto.h
    eeprom_structure.c
    eeprom_structure.h)

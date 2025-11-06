/*! \brief i2c EEPROM
    \author Anatoly Georgievski, 2025
 */

#include <stdint.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/i2c-dev.h>
#include <linux/i2c.h>
#include <unistd.h>

#define EEPROM_PAGE_SIZE 8
static int _write_data(int fd, uint8_t dev_addr, uint8_t reg_addr,  const uint8_t *data, unsigned int len) 
{
	int res = ioctl(fd, I2C_SLAVE, dev_addr);
    return write (fd, data, len);
}
static int _read_data(int fd, uint8_t dev_addr, uint8_t reg_addr,  uint8_t *data, unsigned int len) 
{
	int res = ioctl(fd, I2C_SLAVE, dev_addr);
// такой вариант чтения годится для новых плат и не годится для 1397, возможно стоит читать по одному байту
    return read (fd, data, len); 
}
static int _write_byte(int fd, uint8_t dev_addr, uint8_t cmd){
    int res = 0;
    res = ioctl(fd, I2C_SLAVE, dev_addr);
    struct i2c_smbus_ioctl_data args;
    args.read_write = I2C_SMBUS_WRITE;
    args.command = cmd;
    args.size = I2C_SMBUS_BYTE;
    args.data = NULL;
    return ioctl(fd, I2C_SMBUS, &args);
}
/*! \brief load EEPROM 24C02 256 bytes
    \param i2c_fd - file descriptor
    \param dev_addr - i2c address (0x50+board_index) 
    \param page - 0, start address = page* EEPROM_PAGE_SIZE
    \param data
    \param len <=256 bytes
    \return >=0 - SUCCESS, -1 - FAIL
 */
int  iic_eeprom_load     (int i2c_fd, uint8_t dev_addr, uint8_t page, uint8_t *data, unsigned int len){
    int res = 0;
    int offs = page * EEPROM_PAGE_SIZE;
    res = _write_byte(i2c_fd, dev_addr, offs);
    if (res<0) {
    } else {
        while (offs<256) {
            res = _read_data(i2c_fd, dev_addr, offs, data+offs, EEPROM_PAGE_SIZE);
            offs+=EEPROM_PAGE_SIZE;
        }
    }
    return res;
}
int  iic_open(const char* path, const char* port_settings){
    int fd = open(path, O_RDWR | O_NONBLOCK);
    if (fd < 0) {
        fprintf(stderr, "fail to open i2c port '%s'", path);
        return -1;
    }
    return fd;
}
void iic_close(int i2c_fd){
	close(i2c_fd);
}

#ifndef __DFU_H__
#define __DFU_H__

#include "Serial.h"

class DFU : public Serial
{
public:
    DFU(std::string port) : Serial(port) { }

    bool ping();
    bool set_offset(uint32_t offset);
    bool read_flash(uint32_t offset, uint8_t *buffer, uint8_t size);
    bool read_ob();
    bool set_ob(uint8_t ob);
    bool send_data(uint8_t *buffer);
};

#endif
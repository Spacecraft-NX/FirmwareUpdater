#include "DFU.h"

#undef ERROR_SUCCESS // Fuck windows

enum DFU_ERRORS
{
    ERROR_SUCCESS = 0x70000000,
    ERROR_INVALID_PACKAGE_LENGTH = 0x40000000,
    ERROR_INVALID_OFFSET,
    ERROR_INVALID_LENGTH,
    ERROR_FLASH_FAILED,
    ERROR_FAILED_TO_UPDATE_OB,

    ERROR_UNIMPLEMENTED = 0x50000000
};

enum COMMANDS
{
    PING = 0xA0F0,
    SET_OFFSET,
    READ_FLASH,
    READ_OB,
    SET_OB,
    JUMP_TO_FIRMWARE_HANDLER,
};

bool DFU::ping()
{
    uint8_t outbuffer[2];
    memset(outbuffer, 0, sizeof(outbuffer));

    *(uint16_t*)outbuffer = PING;

    write(outbuffer, sizeof(outbuffer));

    uint8_t inbuffer[4];
    read(inbuffer, sizeof(inbuffer));

    /*printf("%s\n", __func__);
    printf("0x%08x\n", *(uint32_t*)inbuffer);
    printf("\n");*/

    return *(uint32_t*)inbuffer == ERROR_SUCCESS;
}

bool DFU::set_offset(uint32_t offset)
{
    uint8_t outbuffer[6];
    memset(outbuffer, 0, sizeof(outbuffer));

    *(uint16_t*)outbuffer = SET_OFFSET;
    *(uint32_t*)&outbuffer[2] = offset;

    write(outbuffer, sizeof(outbuffer));

    uint8_t inbuffer[4];
    read(inbuffer, sizeof(inbuffer));

    /*printf("%s\n", __func__);
    printf("0x%08x\n", *(uint32_t*)inbuffer);
    printf("\n");*/

    return *(uint32_t*)inbuffer == ERROR_SUCCESS;
}

bool DFU::read_flash(uint32_t offset, uint8_t* buffer, uint8_t size)
{
    uint8_t outbuffer[10];
    memset(outbuffer, 0, sizeof(outbuffer));

    *(uint16_t *)outbuffer = READ_FLASH;
    *(uint32_t*)&outbuffer[2] = offset;
    *(uint32_t*)&outbuffer[6] = size;

    write(outbuffer, sizeof(outbuffer));

    uint8_t inbuffer[4];
    read(inbuffer, sizeof(inbuffer));

    /*printf("%s\n", __func__);
    printf("0x%08x\n", *(uint32_t*)inbuffer);
    printf("\n");
    */

    if (*(uint32_t*)inbuffer == ERROR_SUCCESS)
        read(buffer, size);

    return *(uint32_t*)inbuffer == ERROR_SUCCESS;
}

bool DFU::read_ob()
{
    uint8_t outbuffer[2];
    memset(outbuffer, 0, sizeof(outbuffer));

    *(uint16_t*)outbuffer = READ_OB;

    write(outbuffer, sizeof(outbuffer));

    uint8_t inbuffer[4];
    read(inbuffer, sizeof(inbuffer));

    /*printf("%s\n", __func__);
    printf("0x%08x\n", *(uint32_t*)inbuffer);*/

    if (*(uint32_t*)inbuffer == ERROR_SUCCESS)
    {
        uint8_t inbuffer2[12];
        read(inbuffer2, sizeof(inbuffer2));

        /*for (int i = 0; i < 12; i++)
            printf("0x%02x ", inbuffer2[i]);
        printf("\n\n");*/
    }

    return *(uint32_t*)inbuffer == ERROR_SUCCESS;
}

bool DFU::set_ob(uint8_t ob)
{
    uint8_t outbuffer[3];
    memset(outbuffer, 0, sizeof(outbuffer));

    *(uint16_t*)outbuffer = SET_OB;
    *(uint8_t*)&outbuffer[2] = ob;

    write(outbuffer, sizeof(outbuffer));

    uint8_t inbuffer[4];
    read(inbuffer, sizeof(inbuffer));

    /*printf("%s\n", __func__);
    printf("0x%08x\n", *(uint32_t*)inbuffer);
    printf("\n");*/

    return *(uint32_t*)inbuffer == ERROR_SUCCESS;
}

bool DFU::send_data(uint8_t* buffer)
{
    write(buffer, 64);
    uint8_t inbuffer[4];
    read(inbuffer, sizeof(inbuffer));

    return *(uint32_t*)inbuffer == ERROR_SUCCESS;
}
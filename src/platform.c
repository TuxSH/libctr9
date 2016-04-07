#include <3ds9/common.h>
#include <3ds9/platform.h>

#define CONFIG_PLATFORM_REG ((volatile u32*)0x10140FFC)

Platform GetUnitPlatform()
{
    switch (*CONFIG_PLATFORM_REG) {
        case 7:
            return PLATFORM_N3DS;
        case 1:
        default:
            return PLATFORM_3DS;
    }
}

/*******************************************************************************
 * Copyright (C) 2016 Gabriel Marcano
 *
 * Refer to the COPYING.txt file at the top of the project directory. If that is
 * missing, this file is licensed under the GPL version 2.0 or later.
 *
 ******************************************************************************/

/** @file */

#include <ctr9/ctr_system.h>
#include <ctr9/aes.h>
#include <ctr9/i2c.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdalign.h>

#define PDN_MPCORE_CFG ((volatile uint8_t*)0x10140FFC)
#define PDN_SPI_CNT ((volatile uint8_t*)0x101401C0)

ctr_system_type ctr_get_system_type(void)
{
	//This is seemingly not confirmed on 3dbrew, but it seems PDN_MPCORE_CFG's
	//second and third bit are only set on the N3DS, while the first bit is
	//set for all systems. Use that to detect the type of system.
	return 0x07 == *PDN_MPCORE_CFG ? SYSTEM_N3DS : SYSTEM_O3DS;
}

bool ctr_detect_a9lh_entry(void)
{
	//Aurora determined that this register isn't yet set when a9lh launches.
	return *PDN_SPI_CNT == 0;
}

void ctr_system_poweroff(void)
{
	i2cWriteRegister(I2C_DEV_MCU, 0x20, 1);
	while (true);
}

void ctr_system_reset(void)
{
	i2cWriteRegister(I2C_DEV_MCU, 0x20, 1 << 2);
	while (true);
}

void ctr_twl_keyslot_setup(void)
{
	//Only a9lh really needs to bother with this, and it really only needs to happen once, before ITCM gets messed up.
	static bool setup = false;
	if (!setup && ctr_detect_a9lh_entry())
	{
		uint32_t* TwlCustId = (uint32_t*) (0x01FFB808);
		uint32_t TwlKeyX[4];
		alignas(32) uint8_t TwlKeyY[16];

		// thanks b1l1s & Normmatt
		// see source from https://gbatemp.net/threads/release-twltool-dsi-downgrading-save-injection-etc-multitool.393488/
		const char* nintendo = "NINTENDO";
		TwlKeyX[0] = (TwlCustId[0] ^ 0xB358A6AF) | 0x80000000;
		TwlKeyX[3] = TwlCustId[1] ^ 0x08C267B7;
		memcpy(TwlKeyX + 1, nintendo, 8);

		// see: https://www.3dbrew.org/wiki/Memory_layout#ARM9_ITCM
		uint32_t TwlKeyYW3 = 0xE1A00005;
		memcpy(TwlKeyY, (uint8_t*) 0x01FFD3C8, 12);
		memcpy(TwlKeyY + 12, &TwlKeyYW3, 4);

		setup_aeskeyX(0x03, (uint8_t*)TwlKeyX);
		setup_aeskeyY(0x03, TwlKeyY);
		use_aeskey(0x03);
	}
	setup = true;
}


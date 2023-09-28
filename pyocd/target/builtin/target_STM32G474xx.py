# pyOCD debugger
# Copyright (c) 2023 David van Rijn
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import time
import logging
from collections import defaultdict
from ...coresight.coresight_target import CoreSightTarget
from ...core.memory_map import (FlashRegion, RamRegion, MemoryMap, MemoryType)
from ...coresight.cortex_m import CortexM
from ...coresight.minimal_mem_ap import MinimalMemAP as MiniAP
from ...flash.flash import Flash


LOG = logging.getLogger(__name__)

class DBGMCU:

    BASE =   0xe0042000

    IDC =  BASE + 0x000
    CR =   BASE + 0x004
    CR_VALUE = (0x3f | # keep running in stop sleep and standby
               0x07 << 20 | # enable all debug components
               0x07
               )

    ABP3 = BASE + 0x034

class FlashPeripheral:
    def __init__(self, bank=0):
        assert bank < 2, "only two banks on this device"

        # only per-bank registers are offset
        offset = 0x100 if bank == 1 else 0
        self.bank = bank
        self.flashaddr = 0x2000+0x12000000+0x40000000
        self.flash_keyr      = self.flashaddr + 0x04 + offset
        self.flash_optkeyr   = self.flashaddr + 0x08
        self.flash_optcr     = self.flashaddr + 0x18
        self.flash_cr        = self.flashaddr + 0x0c + offset
        self.flash_sr        = self.flashaddr + 0x10 + offset
        self.flash_optsr_cur = self.flashaddr + 0x1c + offset
        self.flash_optsr_prg = self.flashaddr + 0x20 + offset


FLASH_ALGO = {
    'load_address' : 0x20000000,

    # Flash algorithm as a hex string
    'instructions': [
    0xe7fdbe00,
    0x4d60b570, 0x60a9495e, 0x60a9495f, 0x03c96929, 0x4e5ed4fc, 0x6030444e, 0x8800485d, 0x09800400,
    0x08406070, 0xf00060b0, 0xf44ff896, 0x28016400, 0xf000d104, 0x2801f89f, 0x0064d000, 0x6a2860f4,
    0xd40803c0, 0xf2454853, 0x60015155, 0x60412106, 0x71fff640, 0x20006081, 0x484abd70, 0xf0416941,
    0x61414100, 0x8f4ff3bf, 0x47702000, 0x47702001, 0x49494844, 0x13c16101, 0x69416141, 0x3180f441,
    0xf3bf6141, 0x69018f4f, 0xd4fc03c9, 0x47702000, 0x4605b570, 0xf85ff000, 0x28014e3c, 0xd10a444e,
    0xf868f000, 0xd1062801, 0x683068b1, 0x42a94401, 0x2401d801, 0x2400e000, 0xf84df000, 0xd01b2801,
    0x1e406870, 0x0ae84005, 0x4a33492e, 0x2302610a, 0x00c0eb03, 0x20c4ea40, 0x69486148, 0x3080f440,
    0xf3bf6148, 0x69088f4f, 0xd4fc03c0, 0x40106908, 0x610ad001, 0xbd702001, 0xf83cf000, 0xd0042801,
    0x1e406870, 0x0b284005, 0x68b0e7de, 0xb530e7d9, 0x1dc94b1c, 0xf0214d20, 0x611d0107, 0x615c2401,
    0x6814e011, 0x68546004, 0xf3bf6044, 0x691c8f4f, 0xd4fc03e4, 0x422c691c, 0x611dd002, 0xbd302001,
    0x39083008, 0x29003208, 0x6958d1eb, 0x0001f020, 0x20006158, 0x4811bd30, 0xf3c06800, 0xf5b0000b,
    0xd0056f8d, 0x6080f5a0, 0xd0013879, 0x47702001, 0x47702000, 0x6a004803, 0x5080f3c0, 0x00004770,
    0x45670123, 0x40022000, 0xcdef89ab, 0x00000004, 0x1fff75e0, 0x40003000, 0x000143fa, 0xe0042000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000
    ],

    # Relative function addresses
    'pc_init': 0x20000005,
    'pc_unInit': 0x2000005f,
    'pc_program_page': 0x20000113,
    'pc_erase_sector': 0x20000095,
    'pc_eraseAll': 0x20000075,

    'static_base' : 0x20000000 + 0x00000004 + 0x000001a0,
    'begin_stack' : 0x200019c0,
    'end_stack' : 0x200009c0,
    'begin_data' : 0x20000000 + 0x1000,
    'page_size' : 0x400,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    # Enable double buffering
    'page_buffers' : [
        0x200001c0,
        # for some reason double buffer mode results in a stackoverflow
        #0x200005c0
    ],
    'min_program_length' : 0x400,

    # Relative region addresses and sizes
    'ro_start': 0x4,
    'ro_size': 0x1a0,
    'rw_start': 0x1a4,
    'rw_size': 0x14,
    'zi_start': 0x1b8,
    'zi_size': 0x0,

    # Flash information
    'flash_start': 0x8000000,
    'flash_size': 0x20000,
    'sector_sizes': (
        (0x0, 0x800),
    )
}


class STM32G474xx(CoreSightTarget):

    VENDOR = "STMicroelectronics"

    class FlashSTM32G4(Flash):
        class SectorState:
            Unknown=0,
            Erased=1,
            HalfProgrammed=2,

        FLASH = 0x4002200
        FLASH_OPTR = FLASH + 0x20
        # option byte
        URPOB = 0x1FFF_7800
        BANK1_START = 0x0800_0000

    class FlashCat3(FlashSTM32G4):
        BANK2_START = 0x0804_0000
        def __init__(self, dp, page_size=0x0400, sector_size=0x0800):
            super().__init__()
            self.page_size = page_size
            self.sector_size = sector_size
            self.dp = dp
            self.sector_states = defaultdict(self.SectorState.Unknown)

        #override
        def erase_all(self):
            super().erase()
            self.sector_states = defaultdict(self.SectorState.Erased)

        #override
        def erase_sector(self, address):
            super().erase_sector(address)
            self.sector_states[address] = self.SectorState.Erased

        #override
        def program_page(self, address, bytes):
            sector = address & self.sector_size
            if (self.sector_states[sector]
                    not in (self.SectorState.Erased, self.SectorState.HalfProgrammed)):
                LOG.debug(f"erasing sector {sector:08x} to program page {address:08x}")
                self.erase_sector(address)
            super().program_page(address,bytes)

    MEMORY_MAP = MemoryMap(
        # flash is added by update_memory_map
        #CCM SRAM
        RamRegion(   start=0x1000_0000, length=0x8000,
                  is_cachable=False,
                  access="rwx"),
        #DTCM
        RamRegion(   start=0x2000_0000, length=0x2_0000,
                  is_cachable=False,
                  access="rw"),
        #sram1
        RamRegion(   start=0x3000_0000, length=0x2_0000,
                  is_powered_on_boot=False),
        #sram2
        RamRegion(   start=0x3002_0000, length=0x2_0000,
                  is_powered_on_boot=False),

        #sram3
        RamRegion(   start=0x3004_0000, length=0x8000,
                  is_powered_on_boot=False),
        #sram4
        RamRegion(   start=0x3800_0000, length=0x1_0000),
        )


    def setDualBank(self, dual:bool):
        """
        sets the dual bank mode of the device.
        in single bank mode the two banks are sort of raided together.
        """
        ap = MiniAP(self.dp)
        ap.init()
        optr = ap.read32(self.FLASH_OPTR)
        if dual:
            optr |= 0x0040_0000
        else:
            optr &= ~0x0040_0000
        ap.write32(self.FLASH_OPTR, optr)

    def _verify_memory_map(self,mmap,dbank:bool):
        current_first_bank = mmap.get_region_for_address(self.BANK1_START)
        current_last_bank = mmap.get_region_for_address(self.BANK2_START)

        if dbank:
            return (
                current_first_bank and current_last_bank
                and current_first_bank != current_last_bank
                and current_first_bank.start == self.BANK1_START
                and current_last_bank.start == self.BANK2_START
                )
        else:
            return (
                current_first_bank and current_last_bank
                and current_first_bank == current_last_bank
                and current_first_bank.start == self.BANK1_START
                )

    def update_memory_map(self):
        # we need to read DBANK first, to figure out the memory map
        ap = MiniAP(self.dp)
        ap.init()
        # "User and read protection option bytes" in the g4 reference manual (page 110 in mine)
        optr = ap.read32(self.FLASH_OPTR)
        dbank:bool = optr & 0x0040_0000 != 0

        LOG.debug(f"DBANK is {dbank}")

        if self._verify_memory_map(mmap,dbank):
            return
        LOG.debug("updating memory map because of dbank")

        for region in self.memory_map.iter_matching_regions(type=MemoryType.FLASH):
            self.memory_map.remove_region(region)

        if dbank:
            self.memory_map.add_region(FlashRegion(
                start=0x0800_0000,
                length=0x08_0000,
                sector_size=0x8000,
                page_size=0x800,
                is_boot_memory=True,
                algo=FLASH_ALGO
            ))
        else:
            self.memory_map.add_region(FlashRegion(
                start=0x0800_0000,
                length=0x08_0000,
                sector_size=0x8000,
                page_size=0x1000,
                is_boot_memory=True,
                algo=FLASH_ALGO
            )),


    def __init__(self, session):

        #ap = MiniAP(session.dp)

        super().__init__(session, self.MEMORY_MAP)

    def assert_reset_for_connect(self):
        self.dp.assert_reset(1)

    def safe_reset_and_halt(self):
        assert self.dp.is_reset_asserted()

        # At this point we can't access full AP as it is not initialized yet.
        # Let's create a minimalistic AP and use it.
        ap = MiniAP(self.dp)
        ap.init()

        self.flash = STM32G474xx.FlashCat3(self.dp)
        self.flash.setDualBank(True)
        self.flash.update_memory_map(self.memory_map)

        DEMCR_value = ap.read32(CortexM.DEMCR)

        # Halt on reset.
        ap.write32(CortexM.DEMCR,
                   CortexM.DEMCR_VC_CORERESET |
                   CortexM.DEMCR_TRCENA
                   )
        ap.write32(CortexM.DHCSR, CortexM.DBGKEY | CortexM.C_DEBUGEN)

        self.dp.assert_reset(0)
        time.sleep(0.01)

        DEV_ID = ap.read32(DBGMCU.IDC) & 0xfff

        # these category 1,2,3 respecively
        assert DEV_ID in (0x468,0x469,479), f"IDC.DEV_ID 0x{DEV_ID:03x} did not match expected."

        ap.write32(DBGMCU.CR, DBGMCU.CR_VALUE)

        CR = ap.read32(DBGMCU.CR)
        LOG.info("CR: 0x%08x", CR)

        # Restore DEMCR original value.
        ap.write32(CortexM.DEMCR, DEMCR_value)

    def create_init_sequence(self):
        # this was copied from target_STM32F767xx.py but seems to apply here as well
        #
        # STM32 under some low power/broken clock states doesn't allow AHP communication.
        # Low power modes are quite popular on stm32 (including MBed OS defaults).
        # 'attach' mode is broken by default, as STM32 can't be connected on low-power mode
        #  successfully without previous DBGMCU setup (It is not possible to write DBGMCU).
        # It is also not possible to run full pyOCD discovery code under-reset.
        #
        # As a solution we can setup DBGMCU under reset, halt core and release reset.
        # Unfortunately this code has to be executed _before_ discovery stage
        # and without discovery stage we don't have access to AP/Core.
        # As a solution we can create minimalistic AP implementation and use it
        # to setup core halt.
        # So the sequence for 'halt' connect mode will look like
        # -> Assert reset
        # -> Connect DebugPort
        # -> Setup MiniAp
        # -> Setup halt on reset
        # -> Enable support for debugging in low-power modes
        # -> Release reset
        # -> [Core is halted and reset is released]
        # -> Continue [discovery, create cores, etc]
        seq = super().create_init_sequence()
        if self.session.options.get('connect_mode') in ('halt', 'under-reset'):
            seq.insert_before('dp_init', ('assert_reset_for_connect', self.assert_reset_for_connect))
            seq.insert_after('dp_init', ('safe_reset_and_halt', self.safe_reset_and_halt))

        return seq

    def _unlock_flash_peripheral(self, flash_banks=[0,1]):
        raise NotImplemented("unlock")


    def is_locked(self, flash_banks=[0,1]):
        raise NotImplemented("is_locked")

    def disable_read_protection(self, flash_banks=[0,1]):
        self._unlock_flash_peripheral(flash_banks)
        banks = [FlashPeripheral(n) for n in flash_banks]

        for bank in banks:
            while self.read32(bank.flash_sr) & 1:
                time.sleep(0.1)

            optsr = self.read32(bank.flash_optsr_prg)
            self.write32(bank.flash_optsr_prg, optsr & 0xffff_00ff | 0x0000_aa00)

        # on trigger on both changes
        self.write32(bank.flash_optcr, 2)
        while self.read32(bank.flash_sr) & 1:
            time.sleep(0.1)

        self.reset_and_halt()

    def not_mass_erase(self, flash_banks=[0,1]):
        self._unlock_flash_peripheral(flash_banks)
        banks = [FlashPeripheral(n) for n in flash_banks]

        for bank in banks:
            while self.read32(bank.flash_sr) & 1:
                time.sleep(0.1)

            self.write32(bank.flash_cr, 1<<3 | 3<<4)
            self.write32(bank.flash_cr, 1<<3 | 3<<4 | 1<<7)
            LOG.info("mass_erase banks %i", bank.bank)

        # banks can be erased at the same time
        # so start both,
        # then wait for both
        for bank in banks:
            while self.read32(bank.flash_sr) & 1:
                time.sleep(0.1)
            LOG.info("mass_erase bank %i done", bank.bank)




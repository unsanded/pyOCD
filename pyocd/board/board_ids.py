# pyOCD debugger
# Copyright (c) 2017-2020 Arm Limited
# Copyright (c) 2021 Chris Reed
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

from typing import (NamedTuple, Optional)

class BoardInfo(NamedTuple):
    name: str
    target: Optional[str] = None
    binary: Optional[str] = None
    vendor: Optional[str] = None

BOARD_ID_TO_INFO = {
  # Note: please keep board list sorted by ID!
  #
  # Board ID            Board Name              Target              Test Binary
    "0200": BoardInfo(  "FRDM-KL25Z",           "kl25z",            "l1_kl25z.bin"          ),
    "0201": BoardInfo(  "FRDM-KW41Z",           "kw41z4",           "l1_kw41z4.bin"         ),
    "0202": BoardInfo(  "USB-KW41Z",            "kw41z4",           "l1_kw41z4.bin"         ),
    "0203": BoardInfo(  "TWR-KL28Z72M",         "kl28z",            "l1_kl28z.bin",         ),
    "0204": BoardInfo(  "FRDM-KL02Z",           "kl02z",            "l1_kl02z.bin",         ),
    "0205": BoardInfo(  "FRDM-KL28Z",           "kl28z",            "l1_kl28z.bin",         ),
    "0206": BoardInfo(  "TWR-KE18F",            "ke18f16",          "l1_ke18f16.bin",       ),
    "0210": BoardInfo(  "FRDM-KL05Z",           "kl05z",            "l1_kl05z.bin",         ),
    "0213": BoardInfo(  "FRDM-KE15Z",           "ke15z7",           "l1_ke15z7.bin",        ),
    "0214": BoardInfo(  "Hexiwear",             "k64f",             "l1_k64f.bin",          ),
    "0215": BoardInfo(  "FRDM-KL28ZEM",         "kl28z",            "l1_kl28z.bin",         ),
    "0216": BoardInfo(  "HVP-KE18F",            "ke18f16",          "l1_ke18f16.bin",       ),
    "0217": BoardInfo(  "FRDM-K82F",            "k82f25615",        "l1_k82f.bin",          ),
    "0218": BoardInfo(  "FRDM-KL82Z",           "kl82z7",           "l1_kl82z.bin",         ),
    "0219": BoardInfo(  "TWR-KV46F150M",        "mkv46f256vll16",   None,                   ),
    "0220": BoardInfo(  "FRDM-KL46Z",           "kl46z",            "l1_kl46z.bin",         ),
    "0221": BoardInfo(  "TWR-KV11Z75M",         "kv11z7",           None,                   ),
    "0222": BoardInfo(  "FRDM-KEA128Z",         "skeaz128xxx4",     None,                   ),
    "0223": BoardInfo(  "FRDM-KE02Z",           "mke02z64vlh4",     None,                   ),
    "0224": BoardInfo(  "FRDM-K28F",            "k28f15",           "l1_k28f.bin",          ),
    "0225": BoardInfo(  "FRDM-K32W042",         "k32w042s",         "l1_k32w042s.bin",      ),
    "0226": BoardInfo(  "MIMXRT1020-EVK",       "mimxrt1020",       "l1_mimxrt1020-evk.bin",),
    "0227": BoardInfo(  "MIMXRT1050-EVKB",      "mimxrt1050_hyperflash", "l1_mimxrt1050-evkb_hyperflash.bin",),
    "0228": BoardInfo(  "Rapid-IoT-K64F",       "k64f",             None,                   ),
    "0229": BoardInfo(  "MIMXRT1060-EVK",       "mimxrt1060",       'evkmimxrt1060.bin',    ),
    "0230": BoardInfo(  "FRDM-K20D50M",         "k20d50m",          "l1_k20d50m.bin",       ),
    "0231": BoardInfo(  "FRDM-K22F",            "k22f",             "l1_k22f.bin",          ),
    "0232": BoardInfo(  "MIMXRT1064-EVK",       "mimxrt1064",       'evkmimxrt1064.bin',    ),
    "0233": BoardInfo(  "FRDM-KE16Z",           "mke16z64vlf4",     None,                   ),
    "0234": BoardInfo(  "Rapid-IoT-KW41Z",      "kw41z4",           "l1_kw41z4.bin",        ),
    "0235": BoardInfo(  "LPC54018IoTModule",    "lpc54018jet180",   None,                   ),
    "0236": BoardInfo(  "LPCXpresso55S69",      "lpc55s69",         "lpcxpresso55s69.bin",  ),
    "0237": BoardInfo(  "FRDM-K32L3A6",         "k32l3a60vpj1a",    None,                   ),
    "0238": BoardInfo(  "MIMXRT1024-EVK",       "mimxrt1024",       "evkmimxrt1024.bin",    ),
    "0239": BoardInfo(  "FRDM-K32L2B3",         "k32l2b3",          "l1_frdm_k32l2b3.bin",         ),
    "0240": BoardInfo(  "FRDM-K64F",            "k64f",             "l1_k64f.bin",          ),
    "0241": BoardInfo(  "TWR-KM35Z75M",         "mkm35z512vll7",    None,                   ),
    "0242": BoardInfo(  "MIMXRT1010-EVK",       "mimxrt1010",       "l1_mimxrt1010-evk.bin",),
    "0243": BoardInfo(  "MIMXRT1015-EVK",       "mimxrt1015",       "l1_mimxrt1015-evk.bin",),
    "0244": BoardInfo(  "MIMXRT1170-EVK",       "mimxrt1170_cm7",   "l1_rt1170.bin",          ),
    "0245": BoardInfo(  "IBMEthernetKit",       "k64f",             "l1_k64f.bin"           ),
    "0246": BoardInfo(  "MIMXRT1160-EVK",       "mimxrt1166xxxxx",  None,                   ),
    "0250": BoardInfo(  "FRDM-KW24D512",        "kw24d5",           "l1_kw24d5.bin"         ),
    "0251": BoardInfo(  "FRDM-KW36",            "kw36z4",           "l1_kw36z.bin",         ),
    "0252": BoardInfo(  "FRDM-KW38",            "kw38z4",           None,                   ),
    "0253": BoardInfo(  "USB-KW38",             "kw38z4",           None,                   ),
    "0254": BoardInfo(  "KW38-ER-RD",           "kw38z4",           None,                   ),
    "0260": BoardInfo(  "FRDM-KL26Z",           "kl26z",            "l1_kl26z.bin",         ),
    "0261": BoardInfo(  "FRDM-KL27Z",           "kl27z4",           "l1_kl27z.bin",         ),
    "0262": BoardInfo(  "FRDM-KL43Z",           "kl43z4",           "l1_kl26z.bin",         ),
    "0270": BoardInfo(  "FRDM-KE02Z40M",        "mke02z64vlh4",     None,                   ),
    "0280": BoardInfo(  "TWR-K24F120M",         "mk24fn256vdc12",   None,                   ),
    "0290": BoardInfo(  "FRDM-KW40Z",           "kw40z4",           "l1_kw40z.bin",         ),
    "0291": BoardInfo(  "TWR-KL82Z72M",         "kl82z7",           "l1_kl82z.bin",         ),
    "0298": BoardInfo(  "FRDM-KV10Z",           "kv10z7",           "l1_kl25z.bin"          ),
    "0300": BoardInfo(  "TWR-KV11Z75M",         "kv11z7",           "l1_kl25z.bin"          ),
    "0305": BoardInfo(  "MTS_MDOT_F405RG",      "stm32f405rgtx",    None                    ),
    "0310": BoardInfo(  "MTS_DRAGONFLY_F411RE", "stm32f411retx",    None                    ),
    "0311": BoardInfo(  "FRDM-K66F",            "k66f18",           "l1_k66f.bin",          ),
    "0312": BoardInfo(  "MTS_DRAGONFLY_L471QG", "stm32l471qgix",    None                    ),
    "0315": BoardInfo(  "MTS_MDOT_F411RE",      "stm32f411retx",    None                    ),
    "0320": BoardInfo(  "FRDM-KW01Z9032",       "kw01z4",           "l1_kl26z.bin"          ),
    "0321": BoardInfo(  "USB-KW01Z",            "kw01z4",           "l1_kl25z.bin"          ),
    "0324": BoardInfo(  "USB-KW40Z",            "kw40z4",           "l1_kl25z.bin"          ),
    "0330": BoardInfo(  "TWR-KV58F220M",        "mkv58f512vll24",   None,                   ),
    "0340": BoardInfo(  "TWR-K80F150M",         "mk80fn256vll15",   None,                   ),
    "0341": BoardInfo(  "FRDM-KV31F",           "mkv31f512vll12",   None,                   ),
    "0350": BoardInfo(  "XDOT_L151CC",          "stm32l151cctx",    None                    ),
    "0400": BoardInfo(  "MAXWSNENV",            "max32600",         "l1_maxwsnenv.bin",     ),
    "0405": BoardInfo(  "MAX32600MBED",         "max32600",         "l1_max32600mbed.bin",  ),
    "0406": BoardInfo(  "MAX32620MBED",         "max32620",         None                    ),
    "0407": BoardInfo(  "MAX32620HSP",          "max32620",         None                    ),
    "0408": BoardInfo(  "MAX32625NEXPAQ",       "max32625",         None                    ),
    "0409": BoardInfo(  "MAX32630FTHR",         "max32630",         "max32630fthr.bin",     ),
    "0415": BoardInfo(  "MAX32625MBED",         "max32625",         "max32625mbed.bin",     ),
    "0416": BoardInfo(  "MAX32625PICO",         "max32625",         "max32625pico.bin",     ),
    "0417": BoardInfo(  "MAX32630MBED",         "max32630",         None                    ),
    "0418": BoardInfo(  "MAX32620FTHR",         "max32620",         "max32620fthr.bin",     ),
    "0420": BoardInfo(  "MAX32630HSP3",         "max32630",         None                    ),
    "0421": BoardInfo(  "MAX32660EVSYS",        "max32660",         "max32660evsys.bin",    ),
    "0422": BoardInfo(  "MAX32666FTHR",         "max32666",         "max32666fthr.bin",     ),
    "0424": BoardInfo(  "MAX32670EVKIT",        "max32670",         "max32670evkit.bin",    ),
    "0451": BoardInfo(  "MTB MXChip EMW3166",   "stm32f412xg",      "mtb_mxchip_emw3166.bin",),
    "0459": BoardInfo(  "MTB Advantech WISE-1530", "stm32f412xg",   "mtb_wise-1530.bin",    ),
    "0462": BoardInfo(  "MTB USI WM-BN-BM-22",  "stm32f412xg",      "mtb_usi_wm-bn-bm-22.bin",),
    "0602": BoardInfo(  "EV_COG_AD3029LZ",      "aducm3029",        None                    ),
    "0603": BoardInfo(  "EV_COG_AD4050LZ",      "aducm4050",        None                    ),
    "0604": BoardInfo(  "SDK-K1",               "stm32f469nihx",    None,                   ),
    "0700": BoardInfo(  "NUCLEO-F103RB",        "stm32f103rb",      "ST-Nucleo-F103RB.bin", ),
    "0705": BoardInfo(  "NUCLEO-F302R8",        "stm32f302r8tx",    None,                   ),
    "0710": BoardInfo(  "NUCLEO-L152RE",        "stm32l152re",      "NUCLEO_L152RE.bin",    ),
    "0715": BoardInfo(  "NUCLEO-L053R8",        "stm32l053r8tx",    "NUCLEO_L053R8.bin",    ),
    "0720": BoardInfo(  "NUCLEO-F401RE",        "stm32f401retx",    None,                   ),
    "0725": BoardInfo(  "NUCLEO-F030R8",        "stm32f030r8tx",    None,                   ),
    "0729": BoardInfo(  "NUCLEO-G071RB",        "stm32g071rbtx",    None,                   ),
    "0730": BoardInfo(  "NUCLEO-F072RB",        "stm32f072rbtx",    "NUCLEO_F072RB.bin",    ),
    "0735": BoardInfo(  "NUCLEO-F334R8",        "stm32f334r8tx",    "NUCLEO_F334R8.bin",    ),
    "0740": BoardInfo(  "NUCLEO-F411RE",        "stm32f411retx",    "NUCLEO_F411RE.bin",    ),
    "0742": BoardInfo(  "NUCLEO-F413ZH",        "stm32f413zhtx",    None,                   ),
    "0743": BoardInfo(  "DISCO-F413ZH",         "stm32f413zhtx",    None,                   ),
    "0744": BoardInfo(  "NUCLEO-F410RB",        "stm32f410rbtx",    None,                   ),
    "0745": BoardInfo(  "NUCLEO-F303RE",        "stm32f303retx",    None,                   ),
    "0746": BoardInfo(  "DISCO-F303VC",         "stm32f303vcyx",    None,                   ),
    "0747": BoardInfo(  "NUCLEO-F303ZE",        "stm32f303zetx",    None,                   ),
    "0750": BoardInfo(  "NUCLEO-F091RC",        "stm32f091rctx",    None,                   ),
    "0755": BoardInfo(  "NUCLEO-F070RB",        "stm32f070rbtx",    None,                   ),
    "0760": BoardInfo(  "NUCLEO-L073RZ",        "stm32l073rztx",    None,                   ),
    "0764": BoardInfo(  "DISCO-L475VG-IOT01A",  "stm32l475xg",      "stm32l475vg_iot01a.bin",),
    "0765": BoardInfo(  "NUCLEO-L476RG",        "stm32l476rgtx",    "NUCLEO_L476RG.bin",    ),
    "0770": BoardInfo(  "NUCLEO-L432KC",        "stm32l432kcux",    "NUCLEO_L432KC.bin",    ),
    "0774": BoardInfo(  "DISCO-L4R9I",          "stm32l4r9aiix",    None,                   ),
    "0775": BoardInfo(  "NUCLEO-F303K8",        "stm32f303k8tx",    None,                   ),
    "0776": BoardInfo(  "NUCLEO-L4R5ZI",        "stm32l4r5zitx",    None,                   ),
    "0777": BoardInfo(  "NUCLEO-F446RE",        "stm32f446retx",    None,                   ),
    "0778": BoardInfo(  "NUCLEO-F446ZE",        "stm32f446zetx",    None,                   ),
    "0779": BoardInfo(  "NUCLEO-L433RC-P",      "stm32l433rctx",    None,                   ),
    "0780": BoardInfo(  "NUCLEO-L011K4",        "stm32l011k4tx",    None,                   ),
    "0781": BoardInfo(  "NUCLEO-L4R5ZI-P",      "stm32l4r5zitx",    None,                   ),
    "0783": BoardInfo(  "NUCLEO-L010RB",        "stm32l010rbtx",    None,                   ),
    "0785": BoardInfo(  "NUCLEO-F042K6",        "stm32f042k6tx",    None,                   ),
    "0788": BoardInfo(  "DISCO-F469NI",         "stm32f469nihx",    None,                   ),
    "0790": BoardInfo(  "NUCLEO-L031K6",        "stm32l031x6",      None,                   ),
    "0791": BoardInfo(  "NUCLEO-F031K6",        "stm32f031k6tx",    None,                   ),
    "0795": BoardInfo(  "DISCO-F429ZI",         "stm32f429zitx",    None,                   ),
    "0796": BoardInfo(  "NUCLEO-F429ZI",        "stm32f429xi",      "nucleo_f429zi.bin",    ),
    "0797": BoardInfo(  "NUCLEO-F439ZI",        "stm32f439zitx",    None,                   ),
    "0805": BoardInfo(  "DISCO-L053C8",         "stm32l053c8tx",    None,                   ),
    "0810": BoardInfo(  "DISCO-F334C8",         "stm32f334c8tx",    None,                   ),
    "0812": BoardInfo(  "NUCLEO-F722ZE",        "stm32f722zetx",    None,                   ),
    "0813": BoardInfo(  "NUCLEO-H743ZI",        "stm32h743zitx",    None,                   ),
    "0814": BoardInfo(  "DISCO-H747I",          "stm32h747xihx",    None,                   ),
    "0815": BoardInfo(  "DISCO-F746NG",         "stm32f746nghx",    None,                   ),
    "0816": BoardInfo(  "NUCLEO-F746ZG",        "stm32f746zgtx",    "NUCLEO_F746ZG.bin",    ),
    "0817": BoardInfo(  "DISCO-F769NI",         "stm32f769nihx",    None,                   ),
    "0818": BoardInfo(  "NUCLEO-F767ZI",        "stm32f767zitx",    "NUCLEO_F767ZI.bin",    ),
    "0820": BoardInfo(  "DISCO-L476VG",         "stm32l476vgtx",    None,                   ),
    "0821": BoardInfo(  "NUCLEO-L452RE",        "stm32l452retx",    None,                   ),
    "0822": BoardInfo(  "DISCO-L496AG",         "stm32l496agix",    None,                   ),
    "0823": BoardInfo(  "NUCLEO-L496ZG",        "stm32l496zgtx",    None,                   ),
    "0824": BoardInfo(  "LPCXpresso824-MAX",    "lpc824",           "l1_lpc824.bin",        ),
    "0825": BoardInfo(  "DISCO-F412ZG",         "stm32f412xg",      "nucleo_f412zg.bin",    ),
    "0826": BoardInfo(  "NUCLEO-F412ZG",        "stm32f412xg",      "nucleo_f412zg.bin",    ),
    "0827": BoardInfo(  "NUCLEO-L486RG",        "stm32l486rgtx",    None,                   ),
    "0828": BoardInfo(  "NUCLEO-L496ZG-P",      "stm32l496zgtx",    None,                   ),
    "0829": BoardInfo(  "NUCLEO-L452RE-P",      "stm32l452retx",    None,                   ),
    "0830": BoardInfo(  "DISCO-F407VG",         "stm32f407vgtx",    None,                   ),
    "0833": BoardInfo(  "DISCO-L072CZ-LRWAN1",  "stm32l072cztx",    None,                   ),
    "0835": BoardInfo(  "NUCLEO-F207ZG",        "stm32f207zgtx",    "NUCLEO_F207ZG.bin",    ),
    "0836": BoardInfo(  "NUCLEO-H743ZI2",       "stm32h743zitx",    None,                   ),
    "0839": BoardInfo(  "NUCLEO-WB55RG",        "stm32wb55rgvx",    None,                   ),
    "0840": BoardInfo(  "B96B-F446VE",          "stm32f446vetx",    None,                   ),
    "0841": BoardInfo(  "NUCLEO-G474RE",        "stm32g474retx",    None,                   ),
    "0842": BoardInfo(  "NUCLEO-H753ZI",        "stm32h753zitx",    None,                   ),
    "0843": BoardInfo(  "NUCLEO-H745ZI-Q",      "stm32h745zitx",    None,                   ),
    "0847": BoardInfo(  "DISCO-H745I",          "stm32h745xihx",    None,                   ),
    "0849": BoardInfo(  "NUCLEO-G070RB",        "stm32g070rbtx",    None,                   ),
    "0850": BoardInfo(  "NUCLEO-G431RB",        "stm32g431rbtx",    None,                   ),
    "0851": BoardInfo(  "NUCLEO-G431KB",        "stm32g431kbtx",    None,                   ),
    "0852": BoardInfo(  "NUCLEO-G031K8",        "stm32g031K8tx",    None,                   ),
    "0853": BoardInfo(  "NUCLEO-F301K8",        "stm32f301k8tx",    None,                   ),
    "0854": BoardInfo(  "NUCLEO-L552ZE-Q",      "stm32l552zetxq",   None,                   ),
    "0855": BoardInfo(  "DISCO-L562QE",         "stm32l562qeixq",   None,                   ),
    "0860": BoardInfo(  "NUCLEO-H7A3ZI-Q",      "stm32h7a3zitxq",   None,                   ),
    "0866": BoardInfo(  "NUCLEO-WL55JC",        "stm32wl55jcix",    None,                   ),
    "0879": BoardInfo(  "NUCLEO-F756ZG",        "stm32f756zgtx",    None,                   ),
    "0882": BoardInfo(  "NUCLEO-G491RE",        "stm32g491retx",    None,                   ),
    "0883": BoardInfo(  "NUCLEO-WB15CC",        "stm32wb15ccux",    None,                   ),
    "0884": BoardInfo(  "DISCO-WB5MMG",         "stm32wb5mmghx",    None,                   ),
    "0885": BoardInfo(  "B-L4S5I-IOT01A",       "stm32l4s5vitx",    None,                   ),
    "0886": BoardInfo(  "NUCLEO-U575ZI-Q",      "stm32u575zitx",    None,                   ),
    "0887": BoardInfo(  "B-U585I-IOT02A",       "stm32u585aiix",    None,                   ),
    "1010": BoardInfo(  "mbed NXP LPC1768",     "lpc1768",          "l1_lpc1768.bin",       ),
    "1017": BoardInfo(  "mbed HRM1017",         "nrf51",            "l1_nrf51.bin",         ),
    "1018": BoardInfo(  "Switch-Science-mbed-LPC824", "lpc824",     "l1_lpc824.bin",        ),
    "1019": BoardInfo(  "mbed TY51822r3",       "nrf51",            "l1_nrf51.bin",         ),
    "1040": BoardInfo(  "mbed NXP LPC11U24",    "lpc11u24",         "l1_lpc11u24.bin",      ),
    "1050": BoardInfo(  "NXP LPC800-MAX",       "lpc800",           "l1_lpc800.bin",        ),
    "1054": BoardInfo(  "LPCXpresso54114-MAX",  "lpc54114",         "l1_lpc54114.bin",      ),
    "1056": BoardInfo(  "LPCXpresso54608-MAX",  "lpc54608",         "l1_lpc54608.bin",      ),
    "1060": BoardInfo(  "EA-LPC4088",           "lpc4088qsb",       "l1_lpc4088qsb.bin",    ),
    "1068": BoardInfo(  "LPC11U68",             "lpc11u68jbd100",   None,                   ),
    "1062": BoardInfo(  "EA-LPC4088-Display-Module", "lpc4088dm",   "l1_lpc4088dm.bin",     ),
    "1070": BoardInfo(  "nRF51822-mKIT",        "nrf51",            "l1_nrf51.bin",         ),
    "1080": BoardInfo(  "mBuino",               "lpc11u24",         "l1_lpc11u24.bin",      ),
    "1090": BoardInfo(  "RedBearLab-nRF51822",  "nrf51",            "l1_nrf51.bin",         ),
    "1093": BoardInfo(  "RedBearLab-BLE-Nano2", "nrf52",            "l1_nrf52-dk.bin",      ),
    "1095": BoardInfo(  "RedBearLab-BLE-Nano",  "nrf51",            "l1_nrf51.bin",         ),
    "1100": BoardInfo(  "nRF51-DK",             "nrf51",            "l1_nrf51-dk.bin",      ),
    "1101": BoardInfo(  "nRF52-DK",             "nrf52",            "l1_nrf52-dk.bin",      ),
    "1102": BoardInfo(  "nRF52840-DK",          "nrf52840",         "l1_nrf52840-dk.bin",   ),
    "1114": BoardInfo(  "mbed LPC1114FN28",     "lpc11xx_32",       "l1_mbed_LPC1114FN28.bin",),
    "1120": BoardInfo(  "nRF51-Dongle",         "nrf51",            "l1_nrf51.bin",         ),
    "1200": BoardInfo(  "NCS36510-EVK",         "ncs36510",         "l1_ncs36510-evk.bin",  ),
    "1234": BoardInfo(  "u-blox-C027",          "lpc1768",          "l1_lpc1768.bin",       ),
    "1236": BoardInfo(  "u-blox EVK-ODIN-W2",   "stm32f439xi",      "ublox_evk_odin_w2.bin",),
    "1237": BoardInfo(  "u-blox-EVK-NINA-B1",   "nrf52",            "l1_nrf52-dk.bin",      ),
    "12A0": BoardInfo(  "Calliope-mini",        "nrf51",            None,                   ),
    "1304": BoardInfo(  "NuMaker-PFM-M487",     "m487jidae",        None,                   ),
    "1309": BoardInfo(  "NuMaker-M252KG",       "m252kg6ae",        None,                   ),
    "1310": BoardInfo(  "NuMaker-IoT-M263A",    "m263kiaae",        None,                   ),
    "1312": BoardInfo(  "NuMaker-M2354",        "m2354kjfae",       None,                   ),
    "1313": BoardInfo(  "NuMaker-IoT-M467",     "m467hjhae",        None,                   ),
    "1549": BoardInfo(  "LPC1549",              "lpc1549jbd100",    None,                   ),
    "1600": BoardInfo(  "Bambino 210",          "lpc4330",          "l1_lpc4330.bin",       ),
    "1605": BoardInfo(  "Bambino 210E",         "lpc4330",          "l1_lpc4330.bin",       ),
    "1900": BoardInfo(  "CY8CKIT-062-WIFI-BT",  "cy8c6xx7",         "l1_cy8c6xx7.bin",      ),
    "1901": BoardInfo(  "CY8CPROTO-062-4343W",  "cy8c6xxa",         "l1_cy8c6xxa.bin",      ),
    "1902": BoardInfo(  "CY8CKIT-062-BLE",      "cy8c6xx7",         "l1_cy8c6xx7.bin",      ),
    "1903": BoardInfo(  "CYW9P62S1-43012EVB-01","cy8c6xx7_s25fs512s", "l1_cy8c6xx7.bin",    ),
    "1904": BoardInfo(  "CY8CPROTO-063-BLE",    "cy8c6xx7_nosmif",  "l1_cy8c6xx7.bin",      ),
    "1905": BoardInfo(  "CY8CKIT-062-4343W",    "cy8c6xxa",         "l1_cy8c6xxa.bin",      ),
    "1906": BoardInfo(  "CYW943012P6EVB-01",    "cy8c6xx7",         "l1_cy8c6xx7.bin",      ),
    "1907": BoardInfo(  "CY8CPROTO-064-SB",     "cy8c64xx_cm4_s25hx512t", "l1_cy8c6xx7.bin",),
    "1908": BoardInfo(  "CYW9P62S1-43438EVB-01","cy8c6xx7",         "l1_cy8c6xx7.bin",      ),
    "1909": BoardInfo(  "CY8CPROTO-062S2-43012","cy8c6xxa",         "l1_cy8c6xxa.bin",      ),
    "190A": BoardInfo(  "CY8CKIT-064S2-4343W",  "cy8c64xa_cm4",     "l1_cy8c6xxa.bin",      ),
    "190B": BoardInfo(  "CY8CKIT-062S2-43012",  "cy8c6xxa",         "l1_062S2-43012.bin",   ),
    "190C": BoardInfo(  "CY8CPROTO-064B0S3",    "cy8c64x5_cm4",     "l1_cy8c6xxa.bin",      ),
    "190D": BoardInfo(  "AUGUST_CYW43012",      "cy8c64xx_cm4",     "l1_cy8c6xx7.bin",      ),
    "190E": BoardInfo(  "CY8CPROTO-062S3-4343W","cy8c6xx5",         "l1_cy8c6xxa.bin",      ),
    "190F": BoardInfo(  "CY8CPROTO-064B0S1-BLE","cy8c64xx_cm4_nosmif", "l1_cy8c6xx7.bin",   ),
    "1910": BoardInfo(  "CY8CKIT-064B0S2-4343W","cy8c64xa_cm4",     "l1_cy8c6xxa.bin",      ),
    "1911": BoardInfo(  "CY8CKIT-064S0S2-4343W","cy8c64xa_cm4",     "l1_cy8c6xxa.bin",      ),
    "1912": BoardInfo(  "CYSBSYSKIT-01",        "cy8c6xxa",         "l1_cy8c6xxa.bin",      ),
    "2201": BoardInfo(  "WIZwiki_W7500",        "w7500",            "l1_w7500mbed.bin",     ),
    "2203": BoardInfo(  "WIZwiki_W7500P",       "w7500",            "l1_w7500mbed.bin",     ),
    "2600": BoardInfo(  "ep_agora",             "nrf52840",         None,                   ),
    "3300": BoardInfo(  "CC3220SF_LaunchXL",    "cc3220sf",         "l1_cc3220sf.bin",      ),
    "3701": BoardInfo(  "Samsung_S5JS100",      "s5js100",          "s5js100.bin",          ),
    "4100": BoardInfo(  "NAMote72",             "stm32l152rctx",    None,                   ),
    "4337": BoardInfo(  "LPC4337",              "lpc4337",          None,                   ),
    "4600": BoardInfo(  "Realtek RTL8195AM",    "rtl8195am",        "l1_rtl8195am.bin",     ),
    "5002": BoardInfo(  "Arm V2M-MPS3",         "cortex_m",         None,                   ),
    "5005": BoardInfo(  "Arm V2M-MPS3",         "cortex_m",         None,                   ),
    "5006": BoardInfo(  "Arm Musca-A1",         "musca_a1",         "l1_musca_a1.bin",      ),
    "5007": BoardInfo(  "Arm Musca-B1",         "musca_b1",         "l1_musca_b1.bin",      ),
    "5009": BoardInfo(  "Arm Musca-S1",         "musca_s1",         None,                   ),
    "7402": BoardInfo(  "mbed 6LoWPAN Border Router HAT", "k64f",   "l1_k64f.bin",          ),
    "7778": BoardInfo(  "Teensy 3.1",           "mk20dx256vlh7",    None,                   ),
    "8080": BoardInfo(  "L-Tek FF1705",         "stm32l151cctx",    None,                   ),
    "8081": BoardInfo(  "L-Tek FF-LPC546XX",    "lpc54606",         None,                   ),
    "9004": BoardInfo(  "Arch Pro",             "lpc1768",          "l1_lpc1768.bin",       ),
    "9009": BoardInfo(  "Arch BLE",             "nrf51",            "l1_nrf51.bin",         ),
    "9012": BoardInfo(  "Seeed Tiny BLE",       "nrf51",            "l1_nrf51.bin",         ),
    "9014": BoardInfo(  "Seeed 96Boards Nitrogen", "nrf52",         "l1_nrf52-dk.bin",      ),
    "9900": BoardInfo(  "micro:bit",            "nrf51",            "l1_microbit.bin",      ),
    "9901": BoardInfo(  "micro:bit",            "nrf51",            "l1_microbit.bin",      ),
    "9903": BoardInfo(  "micro:bit v2",         "nrf52833",         "microbitv2.bin",       ),
    "9904": BoardInfo(  "micro:bit v2",         "nrf52833",         "microbitv2.bin",       ),
    "9905": BoardInfo(  "micro:bit v2",         "nrf52833",         "microbitv2.bin",       ),
    "9906": BoardInfo(  "micro:bit v2",         "nrf52833",         "microbitv2.bin",       ),
    "C004": BoardInfo(  "tinyK20",              "k20d50m",          "l1_k20d50m.bin",       ),
    "C006": BoardInfo(  "VBLUno51",             "nrf51",            "l1_nrf51.bin",         ),
}

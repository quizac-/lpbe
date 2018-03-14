#!/usr/bin/env python3

# quizac.gmail.com

import argparse
import dateutil.parser
import grp
import io
import json
import logging
import math
import os
import pwd
import re
import select
import socket
import subprocess
import sys
import time
import traceback
import logging
import logging.handlers
import base64
from collections import namedtuple
from struct import *


START_TIME = int(time.time())
MAX_VRAM_ENTRIES = 24
HOSTNAME            = socket.gethostname().split('.')[0]


BEST_STRAPS = {
    'EDW4032BABG':          '777000000000000022AA1C00315A5B36A0550F15B68C1506004082007C041420CA8980A9020004C01712262B612B3715',
    'H5GC4H24AJR':          '999000000000000022559D0010DE5B4480551312B74C450A00400600750414206A8900A00200312010112D34A42A3816',
    'H5GC4H24AJR_SA_PARTN': '999000000000000022559D0010DE5B4480551312B74C450A00400600750414206A8900A00200312010112D34A42A3816',
    'H5GC8H24MJR':          '777000000000000022AA1C00B56A6D46C0551017BE8E060C006AE6000C081420EA8900AB030000001B162C31C0313F17',
    'H5GQ8H24MJR':          '777000000000000022AA1C00B56A6D46C0551017BE8E060C006AE6000C081420EA8900AB030000001B162C31C0313F17',
    'K4G80325FB':           '777000000000000022CC1C00AD615C41C0590E152ECC8608006007000B031420FA8900A00300000010122F3FBA354019',
    'MT51J256M3':           '777000000000000022AA1C0073626C41B0551016BA0D260B006AE60004061420EA8940AA030000001914292EB22E3B16',
    'MT51J256M32HF':        '777000000000000022AA1C0073626C41B0551016BA0D260B006AE60004061420EA8940AA030000001914292EB22E3B16',
}


MEMORY_IDS = {
    'EDW4032BABG':          'Micron-Elpida',
    'H5GC4H24AJR_SA_PARTN': 'SK_Hynix',
    'H5GC4H24AJR':          'SK_Hynix',
    'H5GC8H24MJR':          'Hynix',
    'H5GQ8H24MJR':          'Hynix',
    'K4G80325FB':           'Samsung',
    'MT51J256M3':           'Micron',
    'MT51J256M32HF':        'Micron',
}


atom_rom_checksum_offset = 0x21
atom_rom_header_ptr = 0x48

ATOM_COMMON_TABLE_HEADER = namedtuple('ATOM_COMMON_TABLE_HEADER', [
    'usStructureSize',
    'ucTableFormatRevision',
    'ucTableContentRevision'
])
ATOM_COMMON_TABLE_HEADER_unpack = '<HBB'
ATOM_COMMON_TABLE_HEADER_size = calcsize(ATOM_COMMON_TABLE_HEADER_unpack)

ATOM_ROM_HEADER = namedtuple('ATOM_ROM_HEADER', ATOM_COMMON_TABLE_HEADER._fields + (
    'uaFirmWareSignature',
    'usBiosRuntimeSegmentAddress',
    'usProtectedModeInfoOffset',
    'usConfigFilenameOffset',
    'usCRC_BlockOffset',
    'usBIOS_BootupMessageOffset',
    'usInt10Offset',
    'usPciBusDevInitCode',
    'usIoBaseAddress',
    'usSubsystemVendorID',
    'usSubsystemID',
    'usPCI_InfoOffset',
    'usMasterCommandTableOffset',
    'usMasterDataTableOffset',
    'ucExtendedFunctionCode',
    'ucReserved',
    'ulPSPDirTableOffset',
    'usVendorID',
    'usDeviceID'
))
ATOM_ROM_HEADER_unpack = ATOM_COMMON_TABLE_HEADER_unpack + 'LHHHHHHHHHHHHHBBLHH'
ATOM_ROM_HEADER_size = calcsize(ATOM_ROM_HEADER_unpack)

ATOM_DATA_TABLES = namedtuple('ATOM_DATA_TABLES', ATOM_COMMON_TABLE_HEADER._fields + (
    'UtilityPipeLine',
    'MultimediaCapabilityInfo',
    'MultimediaConfigInfo',
    'StandardVESA_Timing',
    'FirmwareInfo',
    'PaletteData',
    'LCD_Info',
    'DIGTransmitterInfo',
    'SMU_Info',
    'SupportedDevicesInfo',
    'GPIO_I2C_Info',
    'VRAM_UsageByFirmware',
    'GPIO_Pin_LUT',
    'VESA_ToInternalModeLUT',
    'GFX_Info',
    'PowerPlayInfo',
    'GPUVirtualizationInfo',
    'SaveRestoreInfo',
    'PPLL_SS_Info',
    'OemInfo',
    'XTMDS_Info',
    'MclkSS_Info',
    'Object_Header',
    'IndirectIOAccess',
    'MC_InitParameter',
    'ASIC_VDDC_Info',
    'ASIC_InternalSS_Info',
    'TV_VideoMode',
    'VRAM_Info',
    'MemoryTrainingInfo',
    'IntegratedSystemInfo',
    'ASIC_ProfilingInfo',
    'VoltageObjectInfo',
    'PowerSourceInfo',
    'ServiceInfo'
))
ATOM_DATA_TABLES_unpack = ATOM_COMMON_TABLE_HEADER_unpack + '35H'
ATOM_DATA_TABLES_size = calcsize(ATOM_DATA_TABLES_unpack)

ATOM_POWERPLAY_TABLE = namedtuple('ATOM_POWERPLAY_TABLE', ATOM_COMMON_TABLE_HEADER._fields + (
    'ucTableRevision',
    'usTableSize',
    'ulGoldenPPID',
    'ulGoldenRevision',
    'usFormatID',
    'usVoltageTime',
    'ulPlatformCaps',
    'ulMaxODEngineClock',
    'ulMaxODMemoryClock',
    'usPowerControlLimit',
    'usUlvVoltageOffset',
    'usStateArrayOffset',
    'usFanTableOffset',
    'usThermalControllerOffset',
    'usReserv',
    'usMclkDependencyTableOffset',
    'usSclkDependencyTableOffset',
    'usVddcLookupTableOffset',
    'usVddgfxLookupTableOffset',
    'usMMDependencyTableOffset',
    'usVCEStateTableOffset',
    'usPPMTableOffset',
    'usPowerTuneTableOffset',
    'usHardLimitTableOffset',
    'usPCIETableOffset',
    'usGPIOTableOffset',
    'usReserved',
))
ATOM_POWERPLAY_TABLE_unpack = ATOM_COMMON_TABLE_HEADER_unpack + 'BHLLHHLLL18H'
ATOM_POWERPLAY_TABLE_size = calcsize(ATOM_POWERPLAY_TABLE_unpack)

ATOM_POWERTUNE_TABLE = namedtuple('ATOM_POWERTUNE_TABLE', [
    'ucRevId',
    'usTDP',
    'usConfigurableTDP',
    'usTDC',
    'usBatteryPowerLimit',
    'usSmallPowerLimit',
    'usLowCACLeakage',
    'usHighCACLeakage',
    'usMaximumPowerDeliveryLimit',
    'usTjMax',
    'usPowerTuneDataSetID',
    'usEDCLimit',
    'usSoftwareShutdownTemp',
    'usClockStretchAmount',
    'usTemperatureLimitHotspot',
    'usTemperatureLimitLiquid1',
    'usTemperatureLimitLiquid2',
    'usTemperatureLimitVrVddc',
    'usTemperatureLimitVrMvdd',
    'usTemperatureLimitPlx',
    'ucLiquid1_I2C_address',
    'ucLiquid2_I2C_address',
    'ucLiquid_I2C_Line',
    'ucVr_I2C_address',
    'ucVr_I2C_Line',
    'ucPlx_I2C_address',
    'ucPlx_I2C_Line',
    'usReserved',
])
ATOM_POWERTUNE_TABLE_unpack = '<B19H7BH'
ATOM_POWERTUNE_TABLE_size = calcsize(ATOM_POWERTUNE_TABLE_unpack)

ATOM_MCLK_ENTRY = namedtuple('ATOM_MCLK_ENTRY', [
    'ucVddcInd',
    'usVddci',
    'usVddgfxOffset',
    'usMvdd',
    'ulMclk',
    'usReserved',
])
ATOM_MCLK_ENTRY_unpack = '<BHHHLH'
ATOM_MCLK_ENTRY_size = calcsize(ATOM_MCLK_ENTRY_unpack)

ATOM_MCLK_TABLE = namedtuple('ATOM_MCLK_TABLE', [
    'ucRevId',
    'ucNumEntries',
])
ATOM_MCLK_TABLE_unpack = '<BB'
ATOM_MCLK_TABLE_size = calcsize(ATOM_MCLK_TABLE_unpack)

ATOM_SCLK_ENTRY = namedtuple('ATOM_SCLK_ENTRY', [
    'ucVddInd',
    'usVddcOffset',
    'ulSclk',
    'usEdcCurrent',
    'ucReliabilityTemperature',
    'ucCKSVOffsetandDisable',
    'ulSclkOffset',
    # Polaris Only, remove for compatibility with Fiji
])
ATOM_SCLK_ENTRY_unpack = '<BHLHBBL'
ATOM_SCLK_ENTRY_size = calcsize(ATOM_SCLK_ENTRY_unpack)

ATOM_SCLK_TABLE = namedtuple('ATOM_SCLK_TABLE', [
    'ucRevId',
    'ucNumEntries',
    # ATOM_SCLK_ENTRY entries[ucNumEntries]
])
ATOM_SCLK_TABLE_unpack = '<BB'
ATOM_SCLK_TABLE_size = calcsize(ATOM_SCLK_TABLE_unpack)

ATOM_VOLTAGE_ENTRY = namedtuple('ATOM_VOLTAGE_ENTRY', [
    'usVdd',
    'usCACLow',
    'usCACMid',
    'usCACHigh',
])
ATOM_VOLTAGE_ENTRY_unpack = '<4H'
ATOM_VOLTAGE_ENTRY_size = calcsize(ATOM_VOLTAGE_ENTRY_unpack)

ATOM_VOLTAGE_TABLE = namedtuple('ATOM_VOLTAGE_TABLE', [
    'ucRevId',
    'ucNumEntries',
    # ATOM_VOLTAGE_ENTRY entries[ucNumEntries]
])
ATOM_VOLTAGE_TABLE_unpack = '<BB'
ATOM_VOLTAGE_TABLE_size = calcsize(ATOM_VOLTAGE_TABLE_unpack)


ATOM_VRAM_TIMING_ENTRY = namedtuple('ATOM_VRAM_TIMING_ENTRY', [
    'ulClkRange',
    'ucLatency',
])
ATOM_VRAM_TIMING_ENTRY_unpack = '<L48s'
ATOM_VRAM_TIMING_ENTRY_size = calcsize(ATOM_VRAM_TIMING_ENTRY_unpack)

ATOM_VRAM_ENTRY = namedtuple('ATOM_VRAM_ENTRY', [
    'ulChannelMapCfg',
    'usModuleSize',
    'usMcRamCfg',
    'usEnableChannels',
    'ucExtMemoryID',
    'ucMemoryType',
    'ucChannelNum',
    'ucChannelWidth',
    'ucDensity',
    'ucBankCol',
    'ucMisc',
    'ucVREFI',
    'usReserved',
    'usMemorySize',
    'ucMcTunningSetId',
    'ucRowNum',
    'usEMRS2Value',
    'usEMRS3Value',
    'ucMemoryVenderID',
    'ucRefreshRateFactor',
    'ucFIFODepth',
    'ucCDR_Bandwidth',
    'ulChannelMapCfg1',
    'ulBankMapCfg',
    'ulReserved',
    'strMemPNString',
])
ATOM_VRAM_ENTRY_unpack = '<L3H8B2H2B2H4B3L20s'
ATOM_VRAM_ENTRY_size = calcsize(ATOM_VRAM_ENTRY_unpack)

ATOM_VRAM_INFO = namedtuple('ATOM_VRAM_INFO', ATOM_COMMON_TABLE_HEADER._fields + (
    'usMemAdjustTblOffset',
    'usMemClkPatchTblOffset',
    'usMcAdjustPerTileTblOffset',
    'usMcPhyInitTableOffset',
    'usDramDataRemapTblOffset',
    'usReserved1',
    'ucNumOfVRAMModule',
    'ucMemoryClkPatchTblVer',
    'ucVramModuleVer',
    'ucMcPhyTileNum',
    # ATOM_VRAM_ENTRY aVramInfo[ucNumOfVRAMModule]
))
ATOM_VRAM_INFO_unpack = ATOM_COMMON_TABLE_HEADER_unpack + '6H4B'
ATOM_VRAM_INFO_size = calcsize(ATOM_VRAM_INFO_unpack)


def exception_hook(exc_type, exc_value, exc_traceback):
    log.error('Uncaught exception:')
    tb_output = io.StringIO()
    traceback.print_tb(exc_traceback, None, tb_output)
    exception_out = tb_output.getvalue()
    tb_output.close()

    if exception_out:
        for line in exception_out.splitlines():
            log.error(line)
    else:
        log.error('Traceback is empty')

    log.error('Type: %s' % (repr(exc_type)))
    log.error('Value: %s' % (repr(exc_value)))


def file_write_binary(filename, data, timeout=1):

    if not data:
        log.warn('no data to write to %s' % (filename))
        return False

    try:
        f = open(filename,'wb')
    except Exception as e:
        log.warn('Cannot open wb file %s: %s' % (filename, repr(e)))
        return False

    wrdy = select.select([], [f], [], timeout)[1]
    if f not in wrdy:
        log.warn('Timeout %f seconds reached while writting %s' % (timeout, filename))
        f.close()
        return False

    try:
        written = os.write(f.fileno(), data)
    except Exception as e:
        log.warn('os.write on file %s failed with %s' % (filename, repr(e)))
        f.close()
        return False

    # log.debug('%d B written to %s. data is %d' % (written, filename, len(data)))


    try:
        f.flush()
    except Exception as e:
        log.warn('Cannot flush file %s: %s' % (filename, repr(e)))
        return False
    f.close()

    return True


def file_write(filename, data, timeout=1):

    if not data:
        log.warn('no data to write to %s' % (filename))
        return False

    try:
        f = open(filename,'w')
    except Exception as e:
        log.warn('Cannot open w file %s: %s' % (filename, repr(e)))
        return False

    wrdy = select.select([], [f], [], timeout)[1]
    if f not in wrdy:
        log.warn('Timeout %f seconds reached while writting %s' % (timeout, filename))
        f.close()
        return False

    try:
        written = os.write(f.fileno(), data.encode('UTF-8'))
    except Exception as e:
        log.warn('os.write on file %s failed with %s' % (filename, repr(e)))
        f.close()
        return False

    # log.debug('%d B written to %s. data is %d' % (written, filename, len(data)))


    try:
        f.flush()
    except Exception as e:
        log.warn('Cannot flush file %s: %s' % (filename, repr(e)))
        return False
    f.close()

    return True


def file_read(filename, timeout=1):

    try:
        f = open(filename,'r')
    except Exception as e:
        log.warn('Cannot open file %s: %s' % (filename, repr(e)))
        return None

    rrdy = select.select([f], [], [], timeout)[0]
    if f not in rrdy:
        log.warn('Timeout %f seconds reached while reading %s' % (timeout, filename))
        f.close()
        return None

    try:
        out = os.read(f.fileno(), 1024*1024)
    except Exception as e:
        log.warn('os.read on file %s failed with %s' % (filename, repr(e)))
        f.close()
        return None
    f.close()

    if out:
        out = out.decode('UTF-8')

    return out


def file_read_binary(filename, timeout=1):

    try:
        f = open(filename,'rb')
    except Exception as e:
        log.warn('Cannot open file %s: %s' % (filename, repr(e)))
        return None

    rrdy = select.select([f], [], [], timeout)[0]
    if f not in rrdy:
        log.warn('Timeout %f seconds reached while reading %s' % (timeout, filename))
        f.close()
        return None

    try:
        out = os.read(f.fileno(), 1024*1024)
    except Exception as e:
        log.warn('os.read on file %s failed with %s' % (filename, repr(e)))
        f.close()
        return None
    f.close()

    return out


def exec_shell(command, timeout=10):
    out = None

    try:
        out = subprocess.check_output(command, stderr=subprocess.STDOUT, shell=True, timeout=timeout)
    except Exception as e:
        log.warn('Command %s failed: %s' % (repr(command), repr(e)))

    if out:
        out = out.decode('UTF-8')

    return out


def get_value_at_position(data, bits, position):
    if bits == 8:
        return unpack('<B', data[position:position+1])[0]
    elif bits == 16:
        return unpack('<H', data[position:position+2])[0]


def set_value_at_position(data, bits, position, value):
    if bits == 8:
        raw_value = pack('<B', value)
        new_data = data[:position] + raw_value + data[position+1:]

    return new_data


def bytes_to_string(from_bytes):
    new_string = ''
    for i in range(len(from_bytes)):
        byte = from_bytes[i]
        if byte == 0:
            return new_string
        new_string += chr(byte)

    return new_string


def calculate_new_checksum(bios_data):
    old_checksum = get_value_at_position(bios_data, 8, atom_rom_checksum_offset)
    log.debug('old_checksum=0x%02X' % (old_checksum))

    bios_size = get_value_at_position(bios_data, 8, 2)
    bios_size *= 512
    log.debug('bios_size=%d' % (bios_size))
    offset = 0

    for i in range(bios_size):
        offset += get_value_at_position(bios_data, 8, i)
    offset = offset & 0xFF
    log.debug('offset=%d' % (offset))

    new_checksum = old_checksum - offset;
    new_checksum = new_checksum & 0xFF;
    log.debug('New checksum=0x%02X' % (new_checksum))

    return new_checksum


def copy_bytes(src, dst, skip):
    new_data = dst[:skip] + src + dst[skip+len(src):]
    log.debug('new_data len=%d' % (len(new_data)))

    return new_data


def set_vram_timing_entry(bios_data, offset, atom_vram_timing_entries, atom_vram_entries, tbl, idx, latency):
    if latency == 'BEST':
        vram_model = atom_vram_entries[tbl]['strMemPNString']
        latency = BEST_STRAPS[vram_model]
    ucLatency_bytes = bytes.fromhex(latency)
    log.debug('ucLatency_bytes=%s' % (repr(ucLatency_bytes)))
    atom_vram_timing_entries[idx]['ucLatency'] = ucLatency_bytes
    values = atom_vram_timing_entries[idx].values()
    log.debug('atom_vram_timing_entries[%d].values=%s' % (idx, repr(values)))
    raw_data = pack(ATOM_VRAM_TIMING_ENTRY_unpack, *values)
    bios_data = copy_bytes(raw_data, bios_data, offset)
    atom_vram_timing_entries[idx]['ucLatency'] = latency


def main(args):
    log.debug('fields=%s' % (repr(ATOM_ROM_HEADER._fields)))


    parser = argparse.ArgumentParser()
    parser.add_argument('--in',         dest='input_file',  metavar="FILE")
    parser.add_argument('--out',        dest='output_file', metavar="FILE")
    parser.add_argument('--set-vram',   dest='vram',        nargs='*')
    parser.add_argument('--set-sclk',   dest='sclk',        nargs='*')
    parser.add_argument('--set-mclk',   dest='mclk',        nargs='*')
    options = parser.parse_args(args)
    log.debug(repr(vars(options)))

    if not os.path.exists(options.input_file):
        log.critical('%s does not exist' % (options.input_file))
        sys.exit(1)

    file_size = os.path.getsize(options.input_file)

    if (file_size != 524288) and (file_size != 524288/2):
        log.critical('%s file is non stardard size' % (options.input_file))
        sys.exit(2)

    new_mclk = {}
    if options.mclk:
        # ['1,1000,-', '2,2000,975']
        for v in options.mclk:
            log.debug('v=%s' % (repr(v)))
            k, mhz, mv = v.split(',')
            new_mclk[int(k)] = [ mhz, mv ]
        log.debug('new_mclk=%s' % (repr(new_mclk)))

    new_sclk = {}
    if options.sclk:
        # ['4,1150,-', '5,1150,-']
        for v in options.sclk:
            log.debug('v=%s' % (repr(v)))
            k, mhz, mv = v.split(',')
            new_sclk[int(k)] = [ mhz, mv ]
        log.debug('new_sclk=%s' % (repr(new_sclk)))

    new_vram = {}
    if options.vram:
        # 1,2000,777000000000000022CC1C0031F67E57F05711183FCFB60D006C070124081420FA8900A0030000001E123A46DB354019
        for v in options.vram:
            log.debug('v=%s' % (repr(v)))
            tbl, clk, lat = v.split(',')
            clk = int(clk)
            tbl = int(tbl)
            if len(lat) != 96:
                if 'BEST' not in lat:
                    log.critical('Latency string %s is not 96 characters long. Exiting' % (lat))
                    sys.exit(4)
            if tbl not in new_vram.keys():
                new_vram[tbl] = {}
            new_vram[tbl][clk] = lat
        log.debug('new_vram=%s' % (repr(new_vram)))


    bios_data = file_read_binary(options.input_file)
    # print('header: %s' % (repr(bios_data[0:30])))


    atom_rom_header_offset = get_value_at_position(bios_data, 16, atom_rom_header_ptr)
    log.debug('atom_rom_header_ptr=0x%X' % (atom_rom_header_ptr))
    log.debug('atom_rom_header_offset=0x%04X' % (atom_rom_header_offset))
    atom_rom_header = ATOM_ROM_HEADER._asdict(ATOM_ROM_HEADER._make(unpack(ATOM_ROM_HEADER_unpack, bios_data[atom_rom_header_offset:atom_rom_header_offset+ATOM_ROM_HEADER_size])))
    log.debug('atom_rom_header=%s' % (repr(atom_rom_header)))
    device_id = atom_rom_header['usDeviceID']
    log.debug('device_id=%04X' % (device_id))

    bios_config_filename = bytes_to_string(bios_data[ atom_rom_header['usConfigFilenameOffset']: ])
    bootup_message = bytes_to_string(bios_data[ atom_rom_header['usBIOS_BootupMessageOffset']: ])

    bios_text = ''
    total_length = 0
    for i in range(5):
        content = bytes_to_string(bios_data[0xf4+total_length:])
        log.debug('content=%s' % (content))
        total_length += len(content) + 1
        bios_text += content.strip() + ' '

    bios_text += bios_config_filename
    bios_text = re.sub('(PCI_EXPRESS|POLARIS20|Polaris20)', '', bios_text)
    bios_text = re.sub('\s+', ' ', bios_text)
    bios_text = re.sub('[^A-Za-z0-9]', '_', bios_text)
    log.debug('bios_text=%s' % (bios_text))


    atom_data_table = ATOM_DATA_TABLES._asdict(ATOM_DATA_TABLES._make(unpack(ATOM_DATA_TABLES_unpack,
        bios_data[atom_rom_header['usMasterDataTableOffset']:atom_rom_header['usMasterDataTableOffset']+ATOM_DATA_TABLES_size])))
    log.debug('atom_data_table=%s' % (repr(atom_data_table)))
    atom_powerplay_offset = atom_data_table['PowerPlayInfo']
    log.debug('atom_powerplay_offset=0x%X' % (atom_powerplay_offset))


    atom_powerplay_table = ATOM_POWERPLAY_TABLE._asdict(ATOM_POWERPLAY_TABLE._make(unpack(ATOM_POWERPLAY_TABLE_unpack,
        bios_data[atom_powerplay_offset:atom_powerplay_offset+ATOM_POWERPLAY_TABLE_size])))
    log.debug('atom_powerplay_table=%s' % (repr(atom_powerplay_table)))


    atom_powertune_offset = atom_data_table['PowerPlayInfo'] + atom_powerplay_table['usPowerTuneTableOffset']
    log.debug('atom_powertune_offset=0x%X' % (atom_powertune_offset))
    atom_powertune_table = ATOM_POWERTUNE_TABLE._asdict(ATOM_POWERTUNE_TABLE._make(unpack(ATOM_POWERTUNE_TABLE_unpack,
        bios_data[atom_powertune_offset:atom_powertune_offset+ATOM_POWERTUNE_TABLE_size])))
    log.debug('atom_powertune_table=%s' % (repr(atom_powertune_table)))

    atom_fan_offset = atom_data_table['PowerPlayInfo'] + atom_powerplay_table['usFanTableOffset']
    log.debug('atom_fan_offset=0x%X' % (atom_fan_offset))
    #atom_fan_table = fromBytes<ATOM_FAN_TABLE>(buffer.Skip(atom_fan_offset).ToArray())


    atom_vddc_table_offset = atom_data_table['PowerPlayInfo'] + atom_powerplay_table['usVddcLookupTableOffset']
    log.debug('atom_vddc_table_offset=0x%X' % (atom_vddc_table_offset))
    atom_vddc_table = ATOM_VOLTAGE_TABLE._asdict(ATOM_VOLTAGE_TABLE._make(unpack(ATOM_VOLTAGE_TABLE_unpack,
        bios_data[atom_vddc_table_offset:atom_vddc_table_offset+ATOM_VOLTAGE_TABLE_size])))
    log.debug('atom_vddc_table=%s' % (repr(atom_vddc_table)))


    atom_vddc_entries = []
    atom_vddc_table_ucNumEntries = atom_vddc_table['ucNumEntries']
    for i in range(atom_vddc_table_ucNumEntries):
        offset = atom_vddc_table_offset + ATOM_VOLTAGE_TABLE_size + ( ATOM_VOLTAGE_ENTRY_size * i )
        atom_vddc_entries.append(ATOM_VOLTAGE_ENTRY._asdict(ATOM_VOLTAGE_ENTRY._make(unpack(ATOM_VOLTAGE_ENTRY_unpack,
            bios_data[offset:offset+ATOM_VOLTAGE_ENTRY_size]))))
        log.debug('atom_vddc_entries[%d]=%s' % (i, repr(atom_vddc_entries[i])))


    atom_mclk_table_offset = atom_data_table['PowerPlayInfo'] + atom_powerplay_table['usMclkDependencyTableOffset']
    log.debug('atom_mclk_table_offset=0x%X' % (atom_mclk_table_offset))
    atom_mclk_table = ATOM_MCLK_TABLE._asdict(ATOM_MCLK_TABLE._make(unpack(ATOM_MCLK_TABLE_unpack,
        bios_data[atom_mclk_table_offset:atom_mclk_table_offset+ATOM_MCLK_TABLE_size])))
    log.debug('atom_mclk_table=%s' % (repr(atom_mclk_table)))


    atom_mclk_entries = []
    atom_mclk_table_ucNumEntries = atom_mclk_table['ucNumEntries']
    for i in range(atom_mclk_table_ucNumEntries):
        offset = atom_mclk_table_offset + ATOM_MCLK_TABLE_size + ( ATOM_MCLK_ENTRY_size * i )
        atom_mclk_entries.append(ATOM_MCLK_ENTRY._asdict(ATOM_MCLK_ENTRY._make(unpack(ATOM_MCLK_ENTRY_unpack,
            bios_data[offset:offset+ATOM_MCLK_ENTRY_size]))))
        if options.mclk:
            if i in new_mclk.keys():
                if new_mclk[i][0] != '-':
                    atom_mclk_entries[i]['ulMclk'] = int(new_mclk[i][0])*100
                if new_mclk[i][1] != '-':
                    atom_mclk_entries[i]['usMvdd'] = int(new_mclk[i][1])
                log.info('Setting mclk %d: %s %s' % (i, repr(new_mclk[i][0]), repr(new_mclk[i][1])))
                values = atom_mclk_entries[i].values()
                log.debug('atom_mclk_entries[%d].values=%s' % (i, repr(values)))
                raw_data = pack(ATOM_MCLK_ENTRY_unpack, *values)
                bios_data = copy_bytes(raw_data, bios_data, offset)

    log.debug('atom_mclk_entries=%s' % (repr(atom_mclk_entries)))


    atom_sclk_table_offset = atom_data_table['PowerPlayInfo'] + atom_powerplay_table['usSclkDependencyTableOffset']
    log.debug('atom_sclk_table_offset=0x%X' % (atom_sclk_table_offset))
    atom_sclk_table = ATOM_SCLK_TABLE._asdict(ATOM_SCLK_TABLE._make(unpack(ATOM_SCLK_TABLE_unpack,
        bios_data[atom_sclk_table_offset:atom_sclk_table_offset+ATOM_SCLK_TABLE_size])))
    log.debug('atom_sclk_table=%s' % (repr(atom_sclk_table)))


    atom_sclk_entries = []
    atom_sclk_table_ucNumEntries = atom_sclk_table['ucNumEntries']
    for i in range(atom_sclk_table_ucNumEntries):
        offset = atom_sclk_table_offset + ATOM_SCLK_TABLE_size + ( ATOM_SCLK_ENTRY_size * i )
        atom_sclk_entries.append(ATOM_SCLK_ENTRY._asdict(ATOM_SCLK_ENTRY._make(unpack(ATOM_SCLK_ENTRY_unpack,
            bios_data[offset:offset+ATOM_SCLK_ENTRY_size]))))
        if options.sclk:
            update_sclk = False
            update_vddc = False

            if i in new_sclk.keys():
                if new_sclk[i][0] != '-':
                    atom_sclk_entries[i]['ulSclk'] = int(new_sclk[i][0])*100
                    update_sclk = True
                if new_sclk[i][1] != '-':
                    mv = int(new_sclk[i][1])
                    atom_vddc_entries[ atom_sclk_entries[i]['ucVddInd'] ]['usVdd'] = mv
                    update_vddc = True
                    if mv < 0xFF00:
                        atom_sclk_entries[i]['usVddcOffset'] = 0;
                        update_sclk = True

            if update_sclk:
                log.info('Setting sclk %d: %s %s' % (i, repr(new_sclk[i][0]), repr(new_sclk[i][1])))
                values = atom_sclk_entries[i].values()
                log.debug('atom_sclk_entries[%d].values=%s' % (i, repr(values)))
                raw_data = pack(ATOM_SCLK_ENTRY_unpack, *values)
                bios_data = copy_bytes(raw_data, bios_data, offset)

            if update_vddc:
                vddc_index = atom_sclk_entries[i]['ucVddInd']
                values = atom_vddc_entries[i].values()
                log.debug('atom_vddc_entries[%d].values=%s' % (i, repr(values)))
                raw_data = pack(ATOM_VOLTAGE_ENTRY_unpack, *values)
                offset = atom_vddc_table_offset + ATOM_VOLTAGE_TABLE_size + ( ATOM_VOLTAGE_ENTRY_size * vddc_index )
                bios_data = copy_bytes(raw_data, bios_data, offset)


        log.debug('atom_sclk_entries[%d]=%s' % (i, repr(atom_sclk_entries[i])))



    atom_vram_info_offset = atom_data_table['VRAM_Info']
    log.debug('atom_vram_info_offset=0x%X' % (atom_vram_info_offset))
    atom_vram_info = ATOM_VRAM_INFO._asdict(ATOM_VRAM_INFO._make(unpack(ATOM_VRAM_INFO_unpack,
        bios_data[atom_vram_info_offset:atom_vram_info_offset+ATOM_VRAM_INFO_size])))
    log.debug('atom_vram_info=%s' % (repr(atom_vram_info)))


    atom_vram_entries = []
    atom_vram_info_ucNumOfVRAMModule = atom_vram_info['ucNumOfVRAMModule']
    atom_vram_entry_offset = atom_vram_info_offset + ATOM_VRAM_INFO_size
    for i in range(atom_vram_info_ucNumOfVRAMModule):
        atom_vram_entries.append(ATOM_VRAM_ENTRY._asdict(ATOM_VRAM_ENTRY._make(unpack(ATOM_VRAM_ENTRY_unpack,
            bios_data[atom_vram_entry_offset:atom_vram_entry_offset+ATOM_VRAM_ENTRY_size]))))
        atom_vram_entries[i]['strMemPNString'] = bytes_to_string(atom_vram_entries[i]['strMemPNString'])
        log.debug('atom_vram_entries[%d]=%s' % (i, repr(atom_vram_entries[i])))
        atom_vram_entry_offset += atom_vram_entries[i]['usModuleSize']


    atom_vram_timing_offset = atom_vram_info_offset + atom_vram_info['usMemClkPatchTblOffset'] + 0x2E
    atom_vram_timing_entries = []

    tbl_clk_to_idx_map = {}
    idx_to_offset_map = {}

    for idx in range(MAX_VRAM_ENTRIES):
        log.debug('idx=%d' % (idx))
        offset = atom_vram_timing_offset + ( ATOM_VRAM_TIMING_ENTRY_size * idx )
        idx_to_offset_map[idx] = offset
        atom_vram_timing_entries.append(ATOM_VRAM_TIMING_ENTRY._asdict(ATOM_VRAM_TIMING_ENTRY._make(unpack(ATOM_VRAM_TIMING_ENTRY_unpack,
            bios_data[offset:offset+ATOM_VRAM_TIMING_ENTRY_size]))))
        # atom_vram_timing_entries have an undetermined length
        # attempt to determine the last entry in the array
        ulClkRange = atom_vram_timing_entries[idx]['ulClkRange']
        if ulClkRange == 0:
            del atom_vram_timing_entries[idx]
            break

        ucLatency = atom_vram_timing_entries[idx]['ucLatency']
        log.debug('ucLatency=%s' % (repr(ucLatency)))
        ucLatency_hex = ''

        for x in range(len(ucLatency)):
            ucLatency_hex += '%02X' % (ucLatency[x])
        atom_vram_timing_entries[idx]['ucLatency'] = ucLatency_hex
        log.debug('atom_vram_timing_entries[%d]=%s' % (idx, repr(atom_vram_timing_entries[idx])))

        tbl = ulClkRange >> 24
        if tbl not in tbl_clk_to_idx_map.keys():
            tbl_clk_to_idx_map[tbl] = {}

        if options.vram:
            clk = (ulClkRange & 0x00FFFFFF) / 100
            log.debug('tbl=%d, clk=%d, idx=%d' % (tbl, clk, idx))
            tbl_clk_to_idx_map[tbl][clk] = idx
            if tbl in new_vram.keys():
                if clk in new_vram[tbl].keys():
                    latency = new_vram[tbl][clk]
                    if latency == 'BEST':
                        vram_model = atom_vram_entries[tbl]['strMemPNString']
                        latency = BEST_STRAPS[vram_model]
                    log.info('Setting vram %d: %d %s' % (tbl, clk, latency))
                    ucLatency_bytes = bytes.fromhex(latency)
                    log.debug('ucLatency_bytes=%s' % (repr(ucLatency_bytes)))
                    atom_vram_timing_entries[idx]['ucLatency'] = ucLatency_bytes
                    values = atom_vram_timing_entries[idx].values()
                    log.debug('atom_vram_timing_entries[%d].values=%s' % (idx, repr(values)))
                    raw_data = pack(ATOM_VRAM_TIMING_ENTRY_unpack, *values)
                    bios_data = copy_bytes(raw_data, bios_data, idx_to_offset_map[idx])
                    atom_vram_timing_entries[idx]['ucLatency'] = latency

        log.debug('atom_vram_timing_entries[%d]=%s' % (idx, repr(atom_vram_timing_entries[idx])))


    for tbl in new_vram.keys():
        if tbl not in tbl_clk_to_idx_map.keys():
            log.warn('VRAM table %d: does not exist' % (tbl))
            continue

        for clk_idx in new_vram[tbl].keys():
            if clk_idx >= 0:
                continue
            try:
                clk = list(sorted(tbl_clk_to_idx_map[tbl].keys()))[clk_idx]
            except IndexError:
                log.warn('VRAM %d:%d does not exist' % (tbl, clk_idx))
                continue

            idx = tbl_clk_to_idx_map[tbl][clk]
            log.debug('tbl=%d, clk_idx=%d, clk=%d, idx=%d' % (tbl, clk_idx, clk, idx))
            latency = new_vram[tbl][clk_idx]
            if latency == 'BEST':
                vram_model = atom_vram_entries[tbl]['strMemPNString']
                latency = BEST_STRAPS[vram_model]
            log.info('Setting vram %d: %d %s' % (tbl, clk, latency))
            ucLatency_bytes = bytes.fromhex(latency)
            log.debug('ucLatency_bytes=%s' % (repr(ucLatency_bytes)))
            atom_vram_timing_entries[idx]['ucLatency'] = ucLatency_bytes
            values = atom_vram_timing_entries[idx].values()
            log.debug('atom_vram_timing_entries[%d].values=%s' % (idx, repr(values)))
            raw_data = pack(ATOM_VRAM_TIMING_ENTRY_unpack, *values)
            bios_data = copy_bytes(raw_data, bios_data, idx_to_offset_map[idx])
            atom_vram_timing_entries[idx]['ucLatency'] = latency
            log.debug('atom_vram_timing_entries[%d]=%s' % (idx, repr(atom_vram_timing_entries[idx])))


    # log.debug('atom_vram_timing_entries=%s' % (repr(atom_vram_timing_entries)))
    bios_checksum = get_value_at_position(bios_data, 8, atom_rom_checksum_offset)
    new_checksum = calculate_new_checksum(bios_data)
    bios_data = set_value_at_position(bios_data, 8, atom_rom_checksum_offset, new_checksum)
    print('Old BIOS Checksum=0x%02X' % (bios_checksum))
    print('New BIOS checksum=0x%02X' % (new_checksum))
    print('VendorID=0x%04X' % (atom_rom_header['usVendorID']))
    print('DeviceID=0x%04X' % (atom_rom_header['usDeviceID']))
    print('SubsystemID=0x%04X' % (atom_rom_header['usSubsystemID']))
    print('SubsystemVendorID=0x%04X' % (atom_rom_header['usSubsystemVendorID']))
    print('FirmWareSignature=0x%08X' % (atom_rom_header['uaFirmWareSignature']))
    print('BIOSText=%s' % (bios_text))
    print('Max GPU Frequency (MHz)=%d' % (atom_powerplay_table['ulMaxODEngineClock']/100))
    print('Max Memory Frequency (MHz)=%d' % (atom_powerplay_table['ulMaxODMemoryClock']/100))

    print('TDP=%d' % (atom_powertune_table['usTDP']))
    print('usConfigurableTDP=%d' % (atom_powertune_table['usConfigurableTDP']))
    print('TDC=%d' % (atom_powertune_table['usTDC']))
    print('SmallPowerLimit=%d' % (atom_powertune_table['usSmallPowerLimit']))
    print('LowCACLeakage=%d' % (atom_powertune_table['usLowCACLeakage']))
    print('HighCACLeakage=%d' % (atom_powertune_table['usHighCACLeakage']))
    print('MaximumPowerDeliveryLimit=%d' % (atom_powertune_table['usMaximumPowerDeliveryLimit']))


    print()
    for i in range(len(atom_vddc_entries)):
        print('vddc %d: %d' % (i, atom_vddc_entries[i]['usVdd']))

    print()
    for i in range(atom_sclk_table['ucNumEntries']):
        usVddcOffset = atom_sclk_entries[i]['usVddcOffset']
        ucVddInd = atom_sclk_entries[i]['ucVddInd']
        usVdd = atom_vddc_entries[ucVddInd]['usVdd']
        mV = usVddcOffset - 65535
        if mV == -65535:
            mV = 0
        print('sclk %d: %d %d %d=%dmV(%d)' % (i, atom_sclk_entries[i]['ulSclk']/100, usVdd, ucVddInd, mV, usVddcOffset))

    print()
    for i in range(atom_mclk_table['ucNumEntries']):
        print('mclk %d: %d %d' % (i, atom_mclk_entries[i]['ulMclk']/100, atom_mclk_entries[i]['usMvdd']))

    print()
    for i in range(len(atom_vram_timing_entries)):
        ulClkRange = atom_vram_timing_entries[i]['ulClkRange']
        ucLatency = atom_vram_timing_entries[i]['ucLatency']
        tbl = ulClkRange >> 24
        vram_model = atom_vram_entries[tbl]['strMemPNString']
        vram_brand = MEMORY_IDS[vram_model]
        print('vram %s %s %d:%d %s' % ( vram_brand, vram_model, tbl, (ulClkRange & 0x00FFFFFF) / 100, ucLatency))


    if options.output_file:
        new_bios_size = len(bios_data)
        if (new_bios_size != 524288) and (new_bios_size != 524288/2):
            log.critical('New BIOS size is %d. Something went wrong...' % (new_bios_size))
            sys.exit(3)
        log.info('Writing new BIOS to %s' % (options.output_file))
        file_write_binary(options.output_file, bios_data)
        log.info('Done')

    # check new bios data len

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)


cout = logging.StreamHandler(sys.stdout)
#cout.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(filename)s: %(levelname)s %(module)s.%(funcName)s:%(lineno)d: %(message)r')
cout.setFormatter(formatter)
log.addHandler(cout)

sys.excepthook = exception_hook


if __name__ == "__main__":
    log.debug('Starting')

    args = []
    args += sys.argv[1:]
    main(args)


/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  Copyright (c) 2004, Intel Corporation
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

/**
 * @brief EFI DevicePath GUIDs, structs, and macros.
 */
typedef struct {
  uint8_t Type;
  uint8_t SubType;
  uint8_t Length[2];
} EFI_DEVICE_PATH_PROTOCOL;

typedef struct {
  EFI_DEVICE_PATH_PROTOCOL Header;
  uint32_t PartitionNumber;
  uint64_t PartitionStart;
  uint64_t PartitionSize;
  uint8_t Signature[16];
  uint8_t MBRType;
  uint8_t SignatureType;
} HARDDRIVE_DEVICE_PATH;

#define EFI_END_ENTIRE_DEVICE_PATH 0xff
#define EFI_END_ENTIRE_DEVICE_PATH_SUBTYPE 0xff
#define EFI_END_INSTANCE_DEVICE_PATH 0x01
#define EFI_END_DEVICE_PATH_LENGTH (sizeof(EFI_DEVICE_PATH_PROTOCOL))

#define EfiDevicePathNodeLength(a) (((a)->Length[0]) | ((a)->Length[1] << 8))
#define EfiNextDevicePathNode(a) \
  ((EFI_DEVICE_PATH_PROTOCOL *)(((UINT8 *)(a)) + EfiDevicePathNodeLength(a)))

#define EfiDevicePathType(a) (((a)->Type) & 0x7f)
#define EfiIsDevicePathEndType(a) (EfiDevicePathType(a) == 0x7f)

#define EfiIsDevicePathEndSubType(a) \
  ((a)->SubType == EFI_END_ENTIRE_DEVICE_PATH_SUBTYPE)
#define EfiIsDevicePathEndInstanceSubType(a) \
  ((a)->SubType == EFI_END_INSTANCE_DEVICE_PATH)

#define EfiIsDevicePathEnd(a) \
  (EfiIsDevicePathEndType(a) && EfiIsDevicePathEndSubType(a))
#define EfiIsDevicePathEndInstance(a) \
  (EfiIsDevicePathEndType(a) && EfiIsDevicePathEndInstanceSubType(a))

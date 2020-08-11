/**
 * Copyright (c) 2014-present, The osquery authors
 * Copyright (c) 2004, Intel Corporation
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

/**
 * @brief EFI DevicePath GUIDs, structs, and macros.
 */
#pragma pack(push, 1)
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
#pragma pack(pop)

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

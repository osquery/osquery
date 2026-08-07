/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/binary_reader.h>
#include <osquery/utils/conversions/windows/windows_time.h>
#include <osquery/utils/windows/shellitem.h>

#include <cstdio>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

// Property set GUIDs associated with name entries
const std::string kPropertySets[15] = {"000214A1-0000-0000-C000-000000000046",
                                       "01A3057A-74D6-4E80-BEA7-DC4C212CE50A",
                                       "46588AE2-4CBC-4338-BBFC-139326986DCE",
                                       "4D545058-4FCE-4578-95C8-8698A9BC0F49",
                                       "56A3372E-CE9C-11D2-9F0E-006097C686F6",
                                       "6444048F-4C8B-11D1-8B70-080036B11A03",
                                       "64440490-4C8B-11D1-8B70-080036B11A03",
                                       "64440491-4C8B-11D1-8B70-080036B11A03",
                                       "64440492-4C8B-11D1-8B70-080036B11A03",
                                       "8F052D93-ABCA-4FC5-A5AC-B01DF4DBE598",
                                       "B725F130-47EF-101A-A5F1-02608C9EEBAC",
                                       "D5CDD502-2E9C-101B-9397-08002B2CF9AE",
                                       "D5CDD505-2E9C-101B-9397-08002B2CF9AE",
                                       "EF6B490D-5CD8-437A-AFFC-DA8B60EE4A3C",
                                       "F29F85E0-4FF9-1068-AB91-08002B27B3D9"};
namespace osquery {
std::string guidParse(std::string_view guid_le_bytes) {
  if (guid_le_bytes.size() < 16) {
    return "";
  }
  // GUID layout: little-endian {uint32, uint16, uint16}, then big-endian 8 bytes
  // formatted as XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX.
  const auto* p = reinterpret_cast<const std::uint8_t*>(guid_le_bytes.data());
  char buf[37];
  std::snprintf(buf, sizeof(buf),
                "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                p[3], p[2], p[1], p[0],
                p[5], p[4],
                p[7], p[6],
                p[8], p[9],
                p[10], p[11], p[12], p[13], p[14], p[15]);
  return std::string(buf);
}

ShellFileEntryData fileEntry(const BinaryReader& shell_data) {
  ShellFileEntryData file_entry;

  // Old: find("0400EFBE") in hex. In bytes: find the 4-byte sequence
  // 04 00 EF BE.
  static constexpr std::string_view kExtSig("\x04\x00\xEF\xBE", 4);
  std::size_t ext_pos = shell_data.find(kExtSig);
  if (ext_pos == BinaryReader::npos || ext_pos < 4) {
    LOG(WARNING) << "Could not find supported file entry extension";
    file_entry.path = "[UNSUPPORTED SHELL EXTENSION]";
    return file_entry;
  }
  file_entry.extension_sig = "0400EFBE"; // preserve old string form
  std::size_t entry_offset = ext_pos - 4;

  // Old: version at substr(entry_offset + 4, 4) → entry_offset + 2 bytes;
  // uint16 LE.
  auto version = shell_data.u16_le(entry_offset + 2);
  if (!version || *version < 7) {
    LOG(WARNING) << "Shellitem format unsupported (version < 7)";
    file_entry.path = "[UNSUPPORTED SHELL EXTENSION]";
    return file_entry;
  }
  file_entry.version = static_cast<int>(*version);

  // Old: timestamp at substr(36, 8) if "43465346" found, else substr(16, 8).
  // In bytes: 18 vs 8. The hex strings 43 46 53 46 → bytes 0x43 0x46 0x53 0x46.
  static constexpr std::string_view kCfsf("\x43\x46\x53\x46", 4);
  std::size_t modified_offset =
      shell_data.find(kCfsf) != BinaryReader::npos ? 18 : 8;
  auto modified_bytes = shell_data.bytes(modified_offset, 4);
  if (modified_bytes) {
    // parseFatTime takes a hex string; format the 4 bytes back to hex.
    char hex[9];
    const auto* p = reinterpret_cast<const std::uint8_t*>(modified_bytes->data());
    std::snprintf(hex, sizeof(hex),
                  "%02X%02X%02X%02X", p[0], p[1], p[2], p[3]);
    std::string ts(hex);
    file_entry.dos_modified = (ts == "00000000") ? 0LL : parseFatTime(ts);
  } else {
    file_entry.dos_modified = 0LL;
  }

  // Old: substr(entry_offset + 16, 8) → entry_offset + 8 bytes.
  auto created_bytes = shell_data.bytes(entry_offset + 8, 4);
  if (created_bytes) {
    char hex[9];
    const auto* p = reinterpret_cast<const std::uint8_t*>(created_bytes->data());
    std::snprintf(hex, sizeof(hex),
                  "%02X%02X%02X%02X", p[0], p[1], p[2], p[3]);
    std::string ts(hex);
    file_entry.dos_created = (ts == "00000000") ? 0LL : parseFatTime(ts);
  } else {
    file_entry.dos_created = 0LL;
  }

  // Old: substr(entry_offset + 24, 8) → entry_offset + 12 bytes.
  auto accessed_bytes = shell_data.bytes(entry_offset + 12, 4);
  if (accessed_bytes) {
    char hex[9];
    const auto* p = reinterpret_cast<const std::uint8_t*>(accessed_bytes->data());
    std::snprintf(hex, sizeof(hex),
                  "%02X%02X%02X%02X", p[0], p[1], p[2], p[3]);
    std::string ts(hex);
    file_entry.dos_accessed = (ts == "00000000") ? 0LL : parseFatTime(ts);
  } else {
    file_entry.dos_accessed = 0LL;
  }

  // Old: substr(entry_offset + 32, 4) → entry_offset + 16 bytes; 2 bytes.
  auto identifier_bytes = shell_data.bytes(entry_offset + 16, 2);
  if (identifier_bytes) {
    char hex[5];
    const auto* p = reinterpret_cast<const std::uint8_t*>(identifier_bytes->data());
    std::snprintf(hex, sizeof(hex), "%02X%02X", p[0], p[1]);
    file_entry.identifier = std::string(hex);
  }

  // Old: ntfs_data = substr(entry_offset + 40, 16) → entry_offset + 20 bytes;
  // 16 hex chars → 8 bytes. mft_entry = first 12 hex chars (6 bytes), little-endian.
  // mft_sequence = next 4 hex chars (2 bytes), little-endian.
  auto mft_entry_bytes = shell_data.bytes(entry_offset + 20, 6);
  if (mft_entry_bytes) {
    // Little-endian 48-bit value.
    long long v = 0;
    const auto* p = reinterpret_cast<const std::uint8_t*>(mft_entry_bytes->data());
    for (int i = 5; i >= 0; --i) {
      v = (v << 8) | p[i];
    }
    file_entry.mft_entry = v;
  } else {
    file_entry.mft_entry = 0LL;
  }

  auto mft_seq = shell_data.u16_le(entry_offset + 26);
  file_entry.mft_sequence = mft_seq ? static_cast<int>(*mft_seq) : 0;

  // Old: string_size at substr(entry_offset + 72, 4) → entry_offset + 36;
  // uint16 LE.
  auto string_size = shell_data.u16_le(entry_offset + 36);
  file_entry.string_size = string_size ? static_cast<int>(*string_size) : 0;

  std::size_t name_offset = 0;
  if (file_entry.version >= 9) {
    name_offset = 46; // old: 92 hex chars
  } else if (file_entry.version == 8) {
    name_offset = 42; // old: 84
  } else { // version == 7
    name_offset = 36; // old: 72
  }
  auto name_tail = shell_data.bytes_from(entry_offset + name_offset);
  if (!name_tail) {
    file_entry.path = "[UNSUPPORTED SHELL EXTENSION]";
    return file_entry;
  }
  // Old: find("0000") in the hex tail → first \0\0 in bytes.
  std::size_t end = name_tail->find(std::string_view("\0\0", 2));
  std::string_view utf16 =
      end == std::string_view::npos ? *name_tail : name_tail->substr(0, end);
  file_entry.path = stripNullBytes(utf16);
  return file_entry;
}

// returns property store name or GUID/id if name not found
std::string propertyStore(const BinaryReader& shell_data,
                          const std::vector<std::size_t>& byte_offsets) {
  std::string guid_string;
  for (auto offset : byte_offsets) {
    // Old: substr(offsets + 8, 32) → offsets + 4 bytes, 16 bytes.
    auto guid_bytes = shell_data.bytes(offset + 4, 16);
    if (!guid_bytes) {
      continue;
    }
    guid_string = guidParse(*guid_bytes);

    for (const auto& property_list : kPropertySets) {
      if (guid_string != property_list) {
        continue;
      }
      // Old: substr(offsets + 48, 8) → offsets + 24 bytes; uint32 LE.
      auto name_chars = shell_data.u32_le(offset + 24);
      if (!name_chars) {
        return guid_string;
      }
      // Old: substr(offsets + 74, (size + 1) * 4) — 74 is the odd offset.
      // → offsets + 37 bytes. (size + 1) * 4 hex chars → (size + 1) * 2 bytes.
      auto utf16 = shell_data.bytes(
          offset + 37, (static_cast<std::size_t>(*name_chars) + 1) * 2);
      if (!utf16) {
        return guid_string;
      }
      return stripNullBytes(*utf16);
    }
  }
  return guid_string;
}

namespace {
constexpr std::uint8_t kNetworkShareIdBytes[] = {0x41, 0x42, 0x46, 0x47, 0x4C, 0xC3};
} // namespace

std::string networkShareItem(const BinaryReader& shell_data) {
  // Old code: shell_data.substr(4, 2) compared against kNetworkShareIds.
  // hex offset 4 → byte offset 2.
  auto id = shell_data.u8(2);
  if (!id) {
    return "[UNKNOWN NETWORK SHELL ITEM]";
  }
  bool match = false;
  for (auto v : kNetworkShareIdBytes) {
    if (v == *id) { match = true; break; }
  }
  if (!match) {
    return "[UNKNOWN NETWORK SHELL ITEM]";
  }
  // Old code: substr(10, find("00", 10) - 10) — read from byte offset 5
  // until the next 0x00 byte.
  auto path_start = shell_data.bytes_from(5);
  if (!path_start) {
    return "[UNKNOWN NETWORK SHELL ITEM]";
  }
  std::size_t end = path_start->find('\0');
  std::string_view path =
      end == std::string_view::npos ? *path_start : path_start->substr(0, end);
  return std::string(path);
}

std::string zipContentItem(const BinaryReader& shell_data) {
  // Old: substr(168, 4) → hex offset 168 → byte offset 84; uint16 LE length.
  auto path_size_chars = shell_data.u16_le(84);
  if (!path_size_chars) {
    return "[ZIP PATH DECODE ERROR]";
  }
  // Old: substr(184, path_size * 4) → byte offset 92; size_chars * 2 bytes.
  auto path_bytes = shell_data.bytes(
      92, static_cast<std::size_t>(*path_size_chars) * 2);
  if (!path_bytes) {
    return "[ZIP PATH DECODE ERROR]";
  }
  std::string result = stripNullBytes(*path_bytes);

  // Optional second path. Old: substr(176, 4) → byte offset 88.
  auto second_size_chars = shell_data.u16_le(88);
  if (second_size_chars && *second_size_chars != 0) {
    // Old: substr(184 + path_size*4 + 4, second_path_size * 4)
    //       → byte offset 92 + path_size_chars*2 + 2.
    std::size_t second_offset =
        92 + static_cast<std::size_t>(*path_size_chars) * 2 + 2;
    auto second_bytes = shell_data.bytes(
        second_offset, static_cast<std::size_t>(*second_size_chars) * 2);
    if (!second_bytes) {
      return result + "/[ZIP PATH DECODE ERROR]";
    }
    result += "/";
    result += stripNullBytes(*second_bytes);
  }
  return result;
}

std::string rootFolderItem(const BinaryReader& shell_data) {
  // The GUID lives at byte offset 4 (after sig byte at offset 2 and an
  // intermediate byte). Old code read 32 hex chars at hex offset 8, which
  // corresponds to 16 bytes at byte offset 4.
  auto guid_bytes = shell_data.bytes(4, 16);
  if (!guid_bytes) {
    return "[UNKNOWN ROOT FOLDER]";
  }
  return guidParse(*guid_bytes);
}

std::string driveLetterItem(const BinaryReader& shell_data) {
  // Old code: boost::unhex(substr(6, 6)) — hex offset 6 → byte offset 3,
  // 6 hex chars → 3 bytes. The 3-byte ASCII slice IS the drive name.
  auto volume = shell_data.bytes(3, 3);
  if (!volume) {
    return "[UNKNOWN DRIVE VOLUME]";
  }
  return std::string(*volume);
}

std::string controlPanelCategoryItem(const BinaryReader& shell_data) {
  // Old code read substr(16, 2) — hex offset 16 → byte offset 8.
  auto panel_id = shell_data.u8(8);
  if (!panel_id) {
    return "[UNKNOWN PANEL CATEGORY]";
  }
  switch (*panel_id) {
    case 0x00: return "All Control Panel Items";
    case 0x01: return "Appearance and Personalization";
    case 0x02: return "Hardware and Sound";
    case 0x03: return "Network and Internet";
    case 0x04: return "Sound, Speech, and Audio Devices";
    case 0x05: return "System and Security";
    case 0x06: return "Clock, Language, and Region";
    case 0x07: return "Ease of Access";
    case 0x08: return "Programs";
    case 0x09: return "User Accounts";
    // NB: 0x10 / 0x11 in the old code were the *hex string* "10" / "11",
    // which compares against the decimal 0x10/0x11 here — preserve as-is.
    case 0x10: return "Security Center";
    case 0x11: return "Mobile PC";
    default:
      LOG(WARNING) << "Unknown panel category byte: "
                   << static_cast<int>(*panel_id);
      return "[UNKNOWN PANEL CATEGORY]";
  }
}

std::string controlPanelItem(const BinaryReader& shell_data) {
  // GUID at hex offset 28 → byte offset 14.
  auto guid_bytes = shell_data.bytes(14, 16);
  if (!guid_bytes) {
    return "";
  }
  return guidParse(*guid_bytes);
}

std::vector<std::string> ftpItem(const BinaryReader& shell_data) {
  std::vector<std::string> ftp_data;

  auto unicode = shell_data.u8(3);  // hex offset 6 → byte 3
  auto uri_size_lo = shell_data.u8(4);
  auto uri_size_hi = shell_data.u8(5);
  if (!unicode || !uri_size_lo || !uri_size_hi) {
    ftp_data.push_back("0000000000000000");
    ftp_data.push_back("[UNKNOWN NAME]");
    return ftp_data;
  }
  bool uri_size_zero = (*uri_size_lo == 0 && *uri_size_hi == 0);

  if (uri_size_zero) {
    ftp_data.push_back("0000000000000000");
  } else {
    if (shell_data.size() < 46) { // old: shell_data.size() < 92 hex chars
      LOG(WARNING) << "Unexpected ShellItem URI size";
      ftp_data.push_back("0000000000000000");
      ftp_data.push_back("[UNKNOWN NAME]");
      return ftp_data;
    }
    // Old: substr(28, 16) → hex offset 28 → byte 14, 16 hex chars → 8 bytes.
    // Return as hex string for downstream littleEndianToUnixTime compatibility.
    auto ts_bytes = shell_data.bytes(14, 8);
    if (!ts_bytes) {
      ftp_data.push_back("0000000000000000");
    } else {
      // littleEndianToUnixTime expects a hex string of 16 chars.
      char hex[17];
      const auto* p = reinterpret_cast<const std::uint8_t*>(ts_bytes->data());
      std::snprintf(hex, sizeof(hex),
                    "%02X%02X%02X%02X%02X%02X%02X%02X",
                    p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]);
      ftp_data.emplace_back(hex);
    }
  }

  if (uri_size_zero && *unicode == 0x80) {
    // Old: find("0000", 16) starting at hex offset 16 → byte offset 8.
    // In byte space: find "\0\0" at or after byte offset 8.
    auto tail = shell_data.bytes_from(8);
    if (!tail) {
      ftp_data.push_back("[UNKNOWN NAME]");
      return ftp_data;
    }
    std::size_t end = tail->find(std::string_view("\0\0", 2));
    if (end == std::string_view::npos) {
      ftp_data.push_back("[UNKNOWN NAME]");
      return ftp_data;
    }
    // Old: hostname starts at hex offset 12 (byte 6); end position above
    // is relative to byte 8, so subtract that anchor.
    std::size_t hostname_byte_end = 8 + end;
    auto hostname_bytes = shell_data.bytes(6, hostname_byte_end - 6);
    if (!hostname_bytes) {
      ftp_data.push_back("[UNKNOWN NAME]");
      return ftp_data;
    }
    ftp_data.push_back(stripNullBytes(*hostname_bytes));
    return ftp_data;
  }

  if (shell_data.size() < 46) {
    LOG(WARNING) << "Unexpected ShellItem URI size";
    ftp_data.push_back("[UNKNOWN NAME]");
    return ftp_data;
  }
  // Old: substr(84, 8) → hex offset 84 → byte 42; uint32 LE.
  auto name_chars = shell_data.u32_le(42);
  if (!name_chars || *name_chars == 0) {
    LOG(WARNING) << "Unexpected hostname size";
    ftp_data.push_back("[UNKNOWN NAME]");
    return ftp_data;
  }
  // Old: hostname_size = chars * 4 (UTF-16) or chars * 2 (ASCII) hex chars.
  // In bytes: chars * 2 (UTF-16) or chars * 1 (ASCII).
  std::size_t hostname_bytes_len =
      (*unicode == 0x80) ? static_cast<std::size_t>(*name_chars) * 2
                         : static_cast<std::size_t>(*name_chars);
  // Old: substr(92, hostname_size) → byte offset 46.
  auto hostname_bytes = shell_data.bytes(46, hostname_bytes_len);
  if (!hostname_bytes) {
    ftp_data.push_back("[UNKNOWN NAME]");
    return ftp_data;
  }
  ftp_data.push_back(stripNullBytes(*hostname_bytes));
  return ftp_data;
}

std::string propertyViewDrive(const BinaryReader& shell_data) {
  // Old code: boost::unhex(substr(26, 6)) — hex offset 26 → byte offset 13,
  // 6 hex chars → 3 bytes.
  auto drive = shell_data.bytes(13, 3);
  if (!drive) {
    return "[UNKNOWN USER PROPERTY DRIVE NAME]";
  }
  return std::string(*drive);
}

std::string variableFtp(const BinaryReader& shell_data) {
  // Old: shell_data.substr(76) — name starts at hex offset 76 → byte 38.
  auto name_start = shell_data.bytes_from(38);
  if (!name_start) {
    return "[UNKNOWN VARIABLE FTP NAME]";
  }
  // Old: find("0000") inside the suffix. In bytes: 0x00 0x00.
  std::size_t pos = name_start->find(std::string_view("\0\0", 2));
  if (pos == std::string_view::npos) {
    return "[UNKNOWN VARIABLE FTP NAME]";
  }
  // Old behavior: take everything *from* the 0000 onward (yes, including the
  // null terminator's neighbors). Then strip "00" hex pairs and unhex.
  // Reproduce in byte space:
  std::string_view from_terminator = name_start->substr(pos);
  return stripNullBytes(from_terminator);
}

std::string variableGuid(const BinaryReader& shell_data) {
  // GUID at hex offset 28 → byte offset 14.
  auto guid_bytes = shell_data.bytes(14, 16);
  if (!guid_bytes) {
    return "";
  }
  return guidParse(*guid_bytes);
}

std::string mtpFolder(const BinaryReader& shell_data) {
  // Old: substr(124, 8) at hex offset 124 → byte offset 62; uint32 LE.
  auto length_chars = shell_data.u32_le(62);
  if (!length_chars) {
    return "[UNKNOWN MTP FOLDER NAME]";
  }
  // Old: substr(148, size * 4) → byte offset 74.
  auto utf16 = shell_data.bytes(74, static_cast<std::size_t>(*length_chars) * 2);
  if (!utf16) {
    return "[UNKNOWN MTP FOLDER NAME]";
  }
  return stripNullBytes(*utf16);
}

std::string mtpDevice(const BinaryReader& shell_data) {
  // Old: substr(76, 8) → 8 hex chars at hex offset 76 → 4 bytes at byte
  // offset 38, interpreted as little-endian uint32 length-in-UTF16-chars.
  auto length_chars = shell_data.u32_le(38);
  if (!length_chars) {
    return "[UNKNOWN MTP DEVICE NAME]";
  }
  // Old: substr(108, size * 4). hex offset 108 → byte offset 54.
  // size * 4 hex chars → size * 2 bytes (UTF-16LE).
  auto utf16 = shell_data.bytes(54, static_cast<std::size_t>(*length_chars) * 2);
  if (!utf16) {
    return "[UNKNOWN MTP DEVICE NAME]";
  }
  return stripNullBytes(*utf16);
}

std::string mtpRoot(const BinaryReader& shell_data) {
  // Old: find("000000", 80) starting at hex offset 80 (byte offset 40),
  // then substr(80, end - 80). In byte space: scan from byte offset 40
  // for three consecutive 0x00 bytes; take the slice.
  auto tail = shell_data.bytes_from(40);
  if (!tail) {
    return "[UNKNOWN MTP ROOT NAME]";
  }
  std::size_t end = tail->find(std::string_view("\0\0\0", 3));
  std::string_view utf16 =
      end == std::string_view::npos ? *tail : tail->substr(0, end);
  return stripNullBytes(utf16);
}
} // namespace osquery
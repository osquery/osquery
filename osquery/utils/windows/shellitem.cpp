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
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/conversions/windows/windows_time.h>
#include <osquery/utils/windows/shellitem.h>

#include <boost/algorithm/hex.hpp>
#include <boost/algorithm/string.hpp>

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
std::string guidParse(const std::string& guid_little) {
  std::vector<std::string> guids;
  guids.push_back(guid_little.substr(0, 8));
  guids.push_back(guid_little.substr(8, 4));
  guids.push_back(guid_little.substr(12, 4));

  std::string guid_4 = guid_little.substr(16, 4);
  std::string guid_5 = guid_little.substr(20, 12);

  // The first 16 GUID characters are in litte endian format
  for (auto& guid : guids) {
    std::reverse(guid.begin(), guid.end());
    for (std::size_t i = 0; i < guid.length(); i += 2) {
      std::swap(guid[i], guid[i + 1]);
    }
  }
  std::string guid_string =
      guids[0] + "-" + guids[1] + "-" + guids[2] + "-" + guid_4 + "-" + guid_5;
  return guid_string;
}

std::string guidParseBytes(std::string_view guid_le_bytes) {
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

ShellFileEntryData fileEntry(const std::string& shell_data) {
  size_t offset;
  std::string extension_sig;
  size_t entry_offset = 0;
  // Find "0400EFBE" offset
  if (shell_data.find("0400EFBE") != std::string::npos) {
    offset = shell_data.find("0400EFBE");
    extension_sig = shell_data.substr(offset, 8);
    entry_offset = offset - 8;
  }
  ShellFileEntryData file_entry;

  if (entry_offset <= 0) {
    LOG(WARNING)
        << "Could not find supported file entry extension in shell data: "
        << shell_data;
    file_entry.path = "[UNSUPPORTED SHELL EXTENSION]";
    return file_entry;
  }

  std::string version = shell_data.substr(entry_offset + 4, 4);
  version = swapEndianess(version);
  file_entry.version = tryTo<int>(version, 16).takeOr(0);
  if (file_entry.version < 7) {
    LOG(WARNING) << "Shellitem format unsupported. Expecting version 7 or "
                    "higher: "
                 << shell_data;
    file_entry.path = "[UNSUPPORTED SHELL EXTENSION]";
    return file_entry;
  }
  file_entry.extension_sig = extension_sig;

  // Shell data may contain Users Files folder signature, modified time is at
  // offset 0x18
  std::string timestamp = "";
  if (shell_data.find("43465346") != std::string::npos) {
    timestamp = shell_data.substr(36, 8);
    file_entry.dos_modified =
        (timestamp == "00000000") ? 0LL : parseFatTime(timestamp);
  } else {
    timestamp = shell_data.substr(16, 8);
    file_entry.dos_modified =
        (timestamp == "00000000") ? 0LL : parseFatTime(timestamp);
  }
  timestamp = shell_data.substr(entry_offset + 16, 8);
  file_entry.dos_created =
      (timestamp == "00000000") ? 0LL : parseFatTime(timestamp);
  timestamp = shell_data.substr(entry_offset + 24, 8);
  file_entry.dos_accessed =
      (timestamp == "00000000") ? 0LL : parseFatTime(timestamp);
  file_entry.identifier = shell_data.substr(entry_offset + 32, 4);
  std::string ntfs_data = shell_data.substr(entry_offset + 40, 16);
  std::string mft_entry = ntfs_data.substr(0, 12);
  mft_entry = swapEndianess(mft_entry);

  if (mft_entry == "000000000000") {
    file_entry.mft_entry = 0LL;
  } else {
    file_entry.mft_entry = tryTo<long long>(mft_entry, 16).takeOr(0ll);
  }

  std::string mft_sequence = ntfs_data.substr(12, 4);
  mft_sequence = swapEndianess(mft_sequence);
  if (mft_sequence == "0000") {
    file_entry.mft_sequence = 0;
  } else {
    file_entry.mft_sequence = tryTo<int>(mft_sequence, 16).takeOr(0);
  }

  std::string string_size = shell_data.substr(entry_offset + 72, 4);
  string_size = swapEndianess(string_size);
  file_entry.string_size = tryTo<int>(string_size, 16).takeOr(0);
  int name_offset = 0;
  if (file_entry.version >= 9) {
    name_offset = 92;
  } else if (file_entry.version == 8) {
    name_offset = 84;
  } else if (file_entry.version == 7) {
    name_offset = 72;
  }
  std::string entry_name = shell_data.substr(entry_offset + name_offset);

  // path name ends with 0000 (end of string)
  size_t name_end = entry_name.find("0000");
  std::string shell_name = entry_name.substr(0, name_end);
  // Path is in unicode, extra 00
  boost::erase_all(shell_name, "00");

  // verify the hex string length is even. This fixes issues with 10 base
  // hex values Example 70006900700000... (pip)
  if (shell_name.length() % 2 != 0) {
    shell_name += "0";
  }
  std::string name;
  // Convert hex path to readable string
  try {
    name = boost::algorithm::unhex(shell_name);
  } catch (const boost::algorithm::hex_decode_error& /* e */) {
    LOG(WARNING) << "Failed to decode ShellItem path hex values to string: "
                 << shell_name;
    file_entry.path = "[UNSUPPORTED SHELL EXTENSION]";
    return file_entry;
  }
  file_entry.path = name;
  return file_entry;
}

// returns property store name or GUID/id if name not found
std::string propertyStore(const std::string& shell_data,
                          const std::vector<size_t>& wps_list) {
  std::string guid_string;
  for (const auto& offsets : wps_list) {
    std::string guid_little = shell_data.substr(offsets + 8, 32);
    guid_string = guidParse(guid_little);
    // If GUID property set is found get the property set name
    for (const auto& property_list : kPropertySets) {
      if (guid_string != property_list) {
        continue;
      }
      std::string name_size = shell_data.substr(offsets + 48, 8);
      name_size = swapEndianess(name_size);
      int size = tryTo<int>(name_size, 16).takeOr(0);
      std::string string_hex = shell_data.substr(offsets + 74, (size + 1) * 4);
      boost::erase_all(string_hex, "00");
      std::string name;
      // Convert hex path to readable string
      try {
        name = boost::algorithm::unhex(string_hex);
      } catch (const boost::algorithm::hex_decode_error& /* e */) {
        LOG(WARNING)
            << "Failed to decode Windows Property List hex values to string: "
            << shell_data;
        return guid_string;
      }
      return name;
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
  return guidParseBytes(*guid_bytes);
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
  return guidParseBytes(*guid_bytes);
}

std::vector<std::string> ftpItem(const std::string& shell_data) {
  std::vector<std::string> ftp_data;
  std::string unicode = shell_data.substr(6, 2);
  std::string uri_size = shell_data.substr(8, 4);
  if (uri_size == "0000") {
    ftp_data.push_back("0000000000000000");
  } else {
    if (shell_data.size() < 92) {
      LOG(WARNING) << "Unexpected ShellItem URI size: " << shell_data;
      ftp_data.push_back("0000000000000000");
      ftp_data.push_back("[UNKNOWN NAME]");
      return ftp_data;
    }
    std::string access_time =
        shell_data.substr(28, 16); // shell data contains connection time
    ftp_data.push_back(access_time);
  }

  if (uri_size == "0000" && unicode == "80") {
    // find end of string
    size_t offset = shell_data.find("0000", 16);
    size_t hostname_size = offset - 12;
    std::string ftp_hostname = shell_data.substr(12, hostname_size);
    std::string name;
    boost::erase_all(ftp_hostname, "00");
    try {
      name = boost::algorithm::unhex(ftp_hostname);
    } catch (const boost::algorithm::hex_decode_error& /* e */) {
      LOG(WARNING)
          << "Failed to decode ShellItem URI/FTP hex values to string: "
          << shell_data;
      ftp_data.push_back("[UNKNOWN NAME]");
      return ftp_data;
    }
    ftp_data.push_back(name);
    return ftp_data;
  }

  if (shell_data.size() < 92) {
    LOG(WARNING) << "Unexpected ShellItem URI size: " << shell_data;
    ftp_data.push_back("[UNKNOWN NAME]");
    return ftp_data;
  }
  int hostname_size = 0;
  std::string name_size = shell_data.substr(84, 8);
  name_size = swapEndianess(name_size);
  // find end of string
  if (unicode == "80") {
    hostname_size = tryTo<int>(name_size, 16).takeOr(0) * 4;
  } else {
    hostname_size = tryTo<int>(name_size, 16).takeOr(0) * 2;
  }
  if (hostname_size == 0) {
    LOG(WARNING) << "Unexepcted hostname size: " << shell_data;
    ftp_data.push_back("[UNKNOWN NAME]");
    return ftp_data;
  }
  std::string ftp_hostname = shell_data.substr(92, hostname_size);
  std::string name;
  boost::erase_all(ftp_hostname, "00");

  try {
    name = boost::algorithm::unhex(ftp_hostname);
  } catch (const boost::algorithm::hex_decode_error& /* e */) {
    LOG(WARNING) << "Failed to decode ShellItem URI/FTP hex values to string: "
                 << shell_data;
    ftp_data.push_back("[UNKNOWN NAME]");
    return ftp_data;
  }
  ftp_data.push_back(name);
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
  return guidParseBytes(*guid_bytes);
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
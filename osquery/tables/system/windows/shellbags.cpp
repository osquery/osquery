/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/tables/system/windows/registry.h>
#include <osquery/tables/system/windows/shellbags.h>
#include <osquery/utils/conversions/binary_reader.h>
#include <osquery/utils/conversions/join.h>
#include <osquery/utils/conversions/windows/windows_time.h>
#include <osquery/utils/windows/shellitem.h>

#include <boost/algorithm/hex.hpp>

#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace osquery {
namespace tables {

std::string guidLookup(const std::string& guid);

namespace {

// Extension signatures (4 bytes each). Discovered by scanning the byte buffer;
// each handler compares its extension_sig parameter against these constants
// using cheap std::string_view equality.
constexpr std::string_view kExt0400EFBE("\x04\x00\xEF\xBE", 4);
constexpr std::string_view kExt2600EFBE("\x26\x00\xEF\xBE", 4);
constexpr std::string_view kExt2500EFBE("\x25\x00\xEF\xBE", 4);

// Windows Property Store signature ("1SPS" in ASCII, little-endian header).
constexpr std::string_view kWps("\x31\x53\x50\x53", 4);

// CFSF (Compound File Shell Folder) marker; flags zip-content / user-file-view
// dispatches.
constexpr std::string_view kCfsf("\x43\x46\x53\x46", 4);

// ":\" — drive-letter sanity check.
constexpr std::string_view kColonBackslash("\x3A\x5C", 2);

// UTF-16LE "\usb#" — flags MTP root entries inside the drive-letter branch.
constexpr std::string_view kUsbPrefix(
    "\x5C\x00\x75\x00\x73\x00\x62\x00\x23\x00", 10);

// Variable shell-item sub-format markers (sig=0x00).
constexpr std::string_view kVarGuidMarker("\xEE\xBB\xFE\x23", 4);
constexpr std::string_view kUserPropMarker("\xD5\xDF\xA3\x23", 4);
constexpr std::string_view kSearchMarker1("\x81\x19\x14\x10", 4);
constexpr std::string_view kSearchMarker2("\x00\xEE\xBE\xBE", 4);
constexpr std::string_view kBbafMarker("\xBB\xAF\x93\x3B", 4);
constexpr std::string_view kMtpDeviceMarker("\x05\x05\x20\x31\x10", 5);
constexpr std::string_view kMtpFolderMarker("\x06\x20\x19\x07", 4);

using Handler = void (*)(const BinaryReader& reader,
                         std::string_view extension_sig,
                         std::vector<std::string>& build_shellbag,
                         QueryData& results,
                         Row& r);

// Push file_entry-derived columns. Shared by directory-entry and user-file-view
// handlers.
void emitFileEntry(const ShellFileEntryData& file_entry,
                   std::vector<std::string>& build_shellbag,
                   QueryData& results,
                   Row& r) {
  if (file_entry.path == "[UNSUPPORTED SHELL EXTENSION]") {
    build_shellbag.push_back(file_entry.path);
    r["path"] = osquery::join(build_shellbag, "\\");
    results.push_back(r);
    return;
  }

  r["modified_time"] = BIGINT(file_entry.dos_modified);
  r["created_time"] = BIGINT(file_entry.dos_created);
  r["accessed_time"] = BIGINT(file_entry.dos_accessed);

  build_shellbag.push_back(file_entry.path);
  r["path"] = osquery::join(build_shellbag, "\\");
  r["mft_entry"] = BIGINT(file_entry.mft_entry);
  r["mft_sequence"] = INTEGER(file_entry.mft_sequence);
  results.push_back(r);
}

// Collect every 1SPS offset in the buffer, then defer to propertyStore.
std::string runPropertyStore(const BinaryReader& reader) {
  std::vector<std::size_t> wps_list;
  std::size_t wps = reader.find(kWps);
  while (wps != BinaryReader::npos) {
    wps_list.push_back(wps);
    wps = reader.find(kWps, wps + 1);
  }
  return propertyStore(reader, wps_list);
}

void handleRootFolder(const BinaryReader& reader,
                      std::string_view /*extension_sig*/,
                      std::vector<std::string>& build_shellbag,
                      QueryData& results,
                      Row& r) {
  std::string name;
  std::string full_path;
  auto byte_at_4 = reader.u8(4); // hex offset 8 == byte offset 4
  if (byte_at_4 && *byte_at_4 == 0x2F) { // User Property View Drive
    name = propertyViewDrive(reader);
    // osquery::join adds "\" to entries, remove drive "\"
    name.pop_back();
    build_shellbag.push_back(name);
    full_path = osquery::join(build_shellbag, "\\");
    full_path += "\\";
  } else {
    std::string root_name = rootFolderItem(reader);
    name = guidLookup(root_name);
    build_shellbag.push_back(name);
    full_path = osquery::join(build_shellbag, "\\");
  }
  r["path"] = full_path;
  results.push_back(r);
}

void handleDirectoryEntry(const BinaryReader& reader,
                          std::string_view /*extension_sig*/,
                          std::vector<std::string>& build_shellbag,
                          QueryData& results,
                          Row& r) {
  ShellFileEntryData file_entry = fileEntry(reader);
  emitFileEntry(file_entry, build_shellbag, results, r);
}

void handleDriveLetter(const BinaryReader& reader,
                       std::string_view extension_sig,
                       std::vector<std::string>& build_shellbag,
                       QueryData& results,
                       Row& r) {
  auto byte_at_3 = reader.u8(3); // hex offset 6 == byte offset 3
  if (byte_at_3 && *byte_at_3 == 0x80 &&
      (extension_sig == kExt2600EFBE || extension_sig == kExt2500EFBE ||
       extension_sig.empty())) { // GUID present
    auto guid_bytes = reader.bytes(4, 16); // hex offset 8 == byte offset 4
    if (!guid_bytes) {
      build_shellbag.push_back("[UNKNOWN DRIVE NAME]");
      r["path"] = osquery::join(build_shellbag, "\\");
      results.push_back(r);
      return;
    }
    std::string guid_name = guidLookup(guidParse(*guid_bytes));
    build_shellbag.push_back(guid_name);
    r["path"] = osquery::join(build_shellbag, "\\");
    results.push_back(r);
    return;
  } else if (reader.find(kUsbPrefix) != BinaryReader::npos &&
             extension_sig.empty()) { // \usb#
    std::string name = mtpRoot(reader);
    build_shellbag.push_back(name);
    r["path"] = osquery::join(build_shellbag, "\\");
    results.push_back(r);
    return;
  }

  // Drive letter should have ":\"
  if (reader.find(kColonBackslash) == BinaryReader::npos) {
    build_shellbag.push_back("[UNKNOWN DRIVE NAME]");
    r["path"] = osquery::join(build_shellbag, "\\");
    results.push_back(r);
    return;
  }
  std::string drive_name = driveLetterItem(reader);
  // osquery::join adds "\" to entries, remove drive "\"
  if (!drive_name.empty()) {
    drive_name.pop_back();
  }
  build_shellbag.push_back(drive_name);
  r["path"] = osquery::join(build_shellbag, "\\") + "\\";
  results.push_back(r);
}

void handleControlPanelCategory(const BinaryReader& reader,
                                std::string_view /*extension_sig*/,
                                std::vector<std::string>& build_shellbag,
                                QueryData& results,
                                Row& r) {
  std::string panel = controlPanelCategoryItem(reader);
  build_shellbag.push_back(panel);
  r["path"] = osquery::join(build_shellbag, "\\");
  results.push_back(r);
}

void handleControlPanelItem(const BinaryReader& reader,
                            std::string_view /*extension_sig*/,
                            std::vector<std::string>& build_shellbag,
                            QueryData& results,
                            Row& r) {
  std::string control_guid = controlPanelItem(reader);
  std::string guid_name = guidLookup(control_guid);
  build_shellbag.push_back(guid_name);
  r["path"] = osquery::join(build_shellbag, "\\");
  results.push_back(r);
}

void handleNetworkShare(const BinaryReader& reader,
                        std::string_view /*extension_sig*/,
                        std::vector<std::string>& build_shellbag,
                        QueryData& results,
                        Row& r) {
  std::string network_share = networkShareItem(reader);
  build_shellbag.push_back(network_share);
  r["path"] = osquery::join(build_shellbag, "\\");
  results.push_back(r);
}

void handleFtp(const BinaryReader& reader,
               std::string_view /*extension_sig*/,
               std::vector<std::string>& build_shellbag,
               QueryData& results,
               Row& r) {
  std::vector<std::string> ftp_data = ftpItem(reader);
  long long unix_time = littleEndianToUnixTime(ftp_data[0]);
  build_shellbag.push_back(ftp_data[1]);
  r["path"] = osquery::join(build_shellbag, "\\");
  r["accessed_time"] = BIGINT(unix_time);
  results.push_back(r);
}

// Forward declaration: User-File-View routes to the fallback's
// User-Property-View logic when the CFSF marker is absent.
void handleFallback(const BinaryReader& reader,
                    std::string_view extension_sig,
                    std::vector<std::string>& build_shellbag,
                    QueryData& results,
                    Row& r);

void handleUserFileView(const BinaryReader& reader,
                        std::string_view extension_sig,
                        std::vector<std::string>& build_shellbag,
                        QueryData& results,
                        Row& r) {
  // The legacy if/else only entered the fileEntry path when the CFSF marker
  // (shell_data.find("43465346") != npos) was present. Without it, sig=0x74
  // fell through to the final else — User Property View / unsupported.
  if (reader.find(kCfsf) == BinaryReader::npos) {
    handleFallback(reader, extension_sig, build_shellbag, results, r);
    return;
  }
  ShellFileEntryData file_entry = fileEntry(reader);
  emitFileEntry(file_entry, build_shellbag, results, r);
}

void handleVariable(const BinaryReader& reader,
                    std::string_view /*extension_sig*/,
                    std::vector<std::string>& build_shellbag,
                    QueryData& results,
                    Row& r) {
  if (reader.find(kVarGuidMarker) != BinaryReader::npos) {
    std::string guid_string = variableGuid(reader);
    std::string guid_name = guidLookup(guid_string);
    build_shellbag.push_back(guid_name);
    r["path"] = osquery::join(build_shellbag, "\\");
    results.push_back(r);
    return;
  }

  // Legacy check: shell_data.substr(12, 8) == "05000000" or "05000300".
  // Hex offset 12 == byte offset 6; 4 bytes interpreted little-endian.
  auto type_word = reader.u32_le(6);
  if (type_word && (*type_word == 0x00000005u || *type_word == 0x00030005u)) {
    std::string ftp_name = variableFtp(reader);
    build_shellbag.push_back(ftp_name);
    r["path"] = osquery::join(build_shellbag, "\\");
    results.push_back(r);
    return;
  }

  if (reader.find(kWps) != BinaryReader::npos) {
    // User Property View contains several signatures, data is likely
    // associated with Explorer searches?
    if (reader.find(kUserPropMarker) != BinaryReader::npos ||
        reader.find(kSearchMarker1) != BinaryReader::npos ||
        reader.find(kVarGuidMarker) != BinaryReader::npos ||
        reader.find(kSearchMarker2) != BinaryReader::npos) {
      build_shellbag.push_back("[VARIABLE USER PROPERTY VIEW]");
      r["path"] = osquery::join(build_shellbag, "\\");
      results.push_back(r);
      return;
    }
    std::string property_name = runPropertyStore(reader);
    build_shellbag.push_back(property_name);
    r["path"] = osquery::join(build_shellbag, "\\");
    results.push_back(r);
    return;
  }

  if (reader.find(kMtpDeviceMarker) != BinaryReader::npos) { // MTP Device
    std::string name = mtpDevice(reader);
    build_shellbag.push_back(name);
    r["path"] = osquery::join(build_shellbag, "\\");
    results.push_back(r);
    return;
  }

  if (reader.find(kMtpFolderMarker) != BinaryReader::npos) { // MTP Folder
    std::string name = mtpFolder(reader);
    build_shellbag.push_back(name);
    r["path"] = osquery::join(build_shellbag, "\\");
    results.push_back(r);
    return;
  }

  LOG(WARNING) << "Unknown variable format in shellbag data";
  build_shellbag.push_back("[UNKNOWN VARIABLE FORMAT]");
  r["path"] = osquery::join(build_shellbag, "\\");
  results.push_back(r);
}

void handleFallback(const BinaryReader& reader,
                    std::string_view /*extension_sig*/,
                    std::vector<std::string>& build_shellbag,
                    QueryData& results,
                    Row& r) {
  if (reader.find(kWps) != BinaryReader::npos) {
    if (reader.find(kUserPropMarker) !=
        BinaryReader::npos) { // User Property View
      auto guid_bytes = reader.bytes(113, 16); // hex offset 226 → byte 113
      if (!guid_bytes) {
        build_shellbag.push_back("[USER PROPERTY VIEW]");
        r["path"] = osquery::join(build_shellbag, "\\");
        results.push_back(r);
        return;
      }
      std::string guid_string = guidParse(*guid_bytes);
      std::string guid_name = guidLookup(guid_string);
      build_shellbag.push_back(guid_name);
      r["path"] = osquery::join(build_shellbag, "\\");
      results.push_back(r);
      return;
    }
    // User Property View may have additional other types of signatures, data
    // is likely associated with Explorer searches?
    if (reader.find(kSearchMarker1) != BinaryReader::npos ||
        reader.find(kVarGuidMarker) != BinaryReader::npos ||
        reader.find(kBbafMarker) != BinaryReader::npos ||
        reader.find(kSearchMarker2) != BinaryReader::npos) {
      build_shellbag.push_back("[USER PROPERTY VIEW]");
      r["path"] = osquery::join(build_shellbag, "\\");
      results.push_back(r);
      return;
    }
    std::string property_name = runPropertyStore(reader);
    build_shellbag.push_back(property_name);
    r["path"] = osquery::join(build_shellbag, "\\");
    results.push_back(r);
    return;
  }

  LOG(WARNING) << "Unsupported Shellbag format";
  build_shellbag.push_back("[UNSUPPORTED FORMAT]");
  r["path"] = osquery::join(build_shellbag, "\\");
  results.push_back(r);
}

// sig → handler dispatch table. Keys are the raw sig byte at offset 2.
// Sig values that share a handler list it once per value (no branching inside
// the handler). Anything not present here routes to handleFallback.
const std::unordered_map<std::uint8_t, Handler>& sigHandlers() {
  static const std::unordered_map<std::uint8_t, Handler> kHandlers = {
      {0x1F, handleRootFolder},
      {0x31, handleDirectoryEntry},
      {0x30, handleDirectoryEntry},
      {0x32, handleDirectoryEntry},
      {0x35, handleDirectoryEntry},
      {0xB1, handleDirectoryEntry},
      {0x2F, handleDriveLetter},
      {0x23, handleDriveLetter},
      {0x25, handleDriveLetter},
      {0x29, handleDriveLetter},
      {0x2A, handleDriveLetter},
      {0x2E, handleDriveLetter},
      {0x01, handleControlPanelCategory},
      {0x71, handleControlPanelItem},
      {0xC3, handleNetworkShare},
      {0x41, handleNetworkShare},
      {0x42, handleNetworkShare},
      {0x46, handleNetworkShare},
      {0x47, handleNetworkShare},
      {0x4C, handleNetworkShare},
      {0x61, handleFtp},
      {0x74, handleUserFileView},
      {0x00, handleVariable},
  };
  return kHandlers;
}

} // namespace

constexpr auto kShellBagPath =
    "\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU";
constexpr auto kShellBagPathNtuser =
    "\\Software\\Microsoft\\Windows\\Shell\\BagMRU";

std::string guidLookup(const std::string& guid) {
  QueryData guid_data;
  queryKey("HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\CLSID\\{" + guid + "}",
           guid_data);
  for (const auto& rKey : guid_data) {
    auto key_type = rKey.find("type");
    auto key_path = rKey.find("path");
    if (key_type == rKey.end() || key_path == rKey.end()) {
      continue;
    }
    auto key_name = rKey.at("name");
    if (key_name == "(Default)") {
      if (rKey.at("data") == "") {
        return "{" + guid + "}";
      }
      return rKey.at("data");
    }
  }
  return "{" + guid + "}";
}

void parseShellData(const std::string& shell_data,
                    std::vector<std::string>& build_shellbag,
                    QueryData& results,
                    const std::string& sid,
                    const std::string& source) {
  Row r;
  r["sid"] = sid;
  r["source"] = source;

  // Unhex the registry value once. Anything malformed (odd length, invalid
  // hex chars) is treated as an empty buffer; downstream bounds checks turn
  // every offset into a deterministic fallback string.
  std::string shell_bytes;
  try {
    shell_bytes = boost::algorithm::unhex(shell_data);
  } catch (const boost::algorithm::hex_decode_error&) {
    // Leave shell_bytes empty.
  }
  BinaryReader reader(shell_bytes);

  // Discover the extension signature (if any) as a view over a byte literal.
  std::string_view extension_sig;
  if (reader.find(kExt0400EFBE) != BinaryReader::npos) {
    extension_sig = kExt0400EFBE;
  } else if (reader.find(kExt2600EFBE) != BinaryReader::npos) {
    extension_sig = kExt2600EFBE;
  } else if (reader.find(kExt2500EFBE) != BinaryReader::npos) {
    extension_sig = kExt2500EFBE;
  }

  // Safe sig extraction. Hex offset 4 → byte offset 2.
  auto sig_byte = reader.u8(2);
  if (!sig_byte) {
    build_shellbag.push_back("[MALFORMED SHELL DATA]");
    r["path"] = osquery::join(build_shellbag, "\\");
    results.push_back(r);
    return;
  }

  // Zip-contents check runs BEFORE the sig dispatch because zip-contents
  // shellbags can carry any sig byte. The discriminator is purely positional:
  // a 0x2F at byte 40 (hex offset 80) or byte 38 (hex offset 76), no
  // extension signature, and enough buffer for zipContentItem to parse.
  if (reader.size() > 100 && extension_sig.empty()) {
    auto b40 = reader.u8(40);
    auto b38 = reader.u8(38);
    if ((b40 && *b40 == 0x2F) || (b38 && *b38 == 0x2F)) {
      std::string path = zipContentItem(reader);
      build_shellbag.push_back(path);
      r["path"] = osquery::join(build_shellbag, "\\");
      results.push_back(r);
      return;
    }
  }

  // Special case for sig=0x1F: the legacy code disabled the root-folder
  // branch when a 1SPS marker was also present (those entries fall through
  // to the fallback's User Property View handling).
  if (*sig_byte == 0x1F && reader.find(kWps) != BinaryReader::npos) {
    handleFallback(reader, extension_sig, build_shellbag, results, r);
    return;
  }

  // Special case for directory-entry sigs: they only dispatch when the
  // 0400EFBE extension signature is present. Otherwise fall through.
  if ((*sig_byte == 0x31 || *sig_byte == 0x30 || *sig_byte == 0x32 ||
       *sig_byte == 0x35 || *sig_byte == 0xB1) &&
      extension_sig != kExt0400EFBE) {
    handleFallback(reader, extension_sig, build_shellbag, results, r);
    return;
  }

  // Special case for drive-letter sigs: legacy required extension_sig be
  // empty, 2600EFBE, or 2500EFBE. 0400EFBE drive-letter data is unsupported.
  if ((*sig_byte == 0x2F || *sig_byte == 0x23 || *sig_byte == 0x25 ||
       *sig_byte == 0x29 || *sig_byte == 0x2A || *sig_byte == 0x2E) &&
      !(extension_sig.empty() || extension_sig == kExt2600EFBE ||
        extension_sig == kExt2500EFBE)) {
    handleFallback(reader, extension_sig, build_shellbag, results, r);
    return;
  }

  const auto& handlers = sigHandlers();
  auto it = handlers.find(*sig_byte);
  Handler h = (it != handlers.end()) ? it->second : handleFallback;
  h(reader, extension_sig, build_shellbag, results, r);
}

// Recursively loop through shellbag entries in the Registry
void parseShellbags(const std::string& path,
                    std::vector<std::string>& build_shellbag,
                    QueryData& results,
                    const std::string& sid,
                    const std::string& source) {
  QueryData shellbag_data;
  queryKey(path, shellbag_data);
  for (const auto& rKey : shellbag_data) {
    auto key_type = rKey.find("type");
    auto key_path = rKey.find("path");
    if (key_type == rKey.end() || key_path == rKey.end()) {
      continue;
    }
    // For Shellbags Reg keys the last character is a number
    if (!isdigit(key_path->second.back())) {
      continue;
    }
    if (rKey.at("data") == "") {
      continue;
    }
    parseShellData(rKey.at("data"), build_shellbag, results, sid, source);
    parseShellbags(key_path->second, build_shellbag, results, sid, source);
    if (build_shellbag.size() > 0) {
      build_shellbag.pop_back();
    }
  }
}

void parseRegistry(const std::string& full_path,
                   const std::string& sid,
                   QueryData& results,
                   const std::string& source) {
  QueryData shellbag_results;
  queryKey(full_path, shellbag_results);
  for (const auto& uKey : shellbag_results) {
    auto key_type = uKey.find("type");
    auto key_path = uKey.find("path");
    if (key_type == uKey.end() || key_path == uKey.end()) {
      continue;
    }
    if (!isdigit(key_path->second.back())) {
      continue;
    }

    if (uKey.at("data") == "") {
      continue;
    }
    std::vector<std::string> build_shellbag;
    parseShellData(uKey.at("data"), build_shellbag, results, sid, source);
    parseShellbags(key_path->second, build_shellbag, results, sid, source);
  }
}

QueryData genShellbags(QueryContext& context) {
  QueryData users;
  QueryData results;

  queryKey("HKEY_USERS", users);
  for (const auto& rKey : users) {
    auto key_type = rKey.find("type");
    auto key_path = rKey.find("path");
    if (key_type == rKey.end() || key_path == rKey.end()) {
      continue;
    }
    std::string full_path = key_path->second + kShellBagPath;
    size_t sid_start = full_path.find("S-");
    if (sid_start == std::string::npos) {
      continue;
    }
    size_t sid_end = full_path.find("_", sid_start);
    if (sid_end == std::string::npos) {
      sid_end = full_path.find("\\", sid_start);
    }
    std::string sid = full_path.substr(sid_start, sid_end - sid_start);
    // Shellbags may exist in both SID_Classes (UsrClass.dat) and SID
    // (NTUSER.dat) Keys but the paths are different
    if (full_path.find("_Classes") == std::string::npos) {
      full_path = key_path->second + kShellBagPathNtuser;
      std::string source = "ntuser.dat";
      parseRegistry(full_path, sid, results, source);
      continue;
    }
    std::string source = "usrclass.dat";
    parseRegistry(full_path, sid, results, source);
  }
  return results;
}
} // namespace tables
} // namespace osquery

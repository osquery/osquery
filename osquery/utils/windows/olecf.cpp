/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/conversions/windows/windows_time.h>
#include <osquery/utils/windows/olecf.h>

#include <boost/algorithm/hex.hpp>
#include <boost/algorithm/string.hpp>

#include <math.h>
#include <string>
#include <string_view>
#include <vector>

namespace osquery {

// Header is 512 bytes
struct OlecfHeader {
  char sig[8];
  char guid[16];
  short revision_minor;
  short revision_major;
  short byte_order;
  int sector_size;
  int short_sector_size;
  int total_sectors;
  int sector_sid;
  int sector_size_stream;
  int sector_sid_ssat;
  int total_sectors_ssat;
  int sector_sid_msat;
  int total_sectors_msat;
  char msat[436];
};

// Directory entries are 128 bytes
struct OleDirectory {
  wchar_t name[32];
  short name_size;
  char dir_type;
  char dir_color;
  int previous_dir;
  int next_dir;
  int sub_dir;
  char class_identifier[16];
  int user_flags;
  char creation_time[8];
  char modified_time[8];
  int sector_sid;
  int directory_size;
  int reserved;
};

struct OleDestListHeader {
  int version;
  int entries;
  int pinned_entries;
  int unknown;
  int last_entry;
  int unknown2;
  int revision;
  int unknown3;
};

struct OleDestList {
  char unknown[8];
  char droid_volume[16];
  char droid_file[16];
  char birth_droid_volume[16];
  char birth_droid_file[16];
  char hostname[16];
  int entry_number;
  int unknown2;
  int unknown3;
  char modified_time[8];
  int pin_status;
  int unknown4;
  int interaction_count;
  char unknown5[8];
  short path_size;
};

struct OleDestListFull {
  OleDestListHeader header;
  std::vector<OleDestList> list;
  std::vector<std::string> path;
};

const unsigned int kOlecfHeaderSize = 512;
const unsigned int kDirectorySize = 128;

OlecfHeader parseOlecfHeader(const std::vector<char>& header_data) {
  OlecfHeader header;
  memcpy(&header.sig, &header_data[0], sizeof(header.sig));
  memcpy(&header.guid, &header_data[8], sizeof(header.guid));
  memcpy(
      &header.revision_minor, &header_data[24], sizeof(header.revision_minor));
  memcpy(
      &header.revision_major, &header_data[26], sizeof(header.revision_major));
  memcpy(&header.byte_order, &header_data[28], sizeof(header.byte_order));
  short size = 0;
  memcpy(&size, &header_data[30], sizeof(size));
  // Sector size should always be 512
  header.sector_size = (int)std::pow(2, size);

  memcpy(&size, &header_data[32], 2);
  // Short sectory size should be 64
  header.short_sector_size = (int)std::pow(2, size);
  memcpy(&header.total_sectors, &header_data[44], sizeof(header.total_sectors));
  memcpy(&header.sector_sid, &header_data[48], sizeof(header.sector_sid));
  memcpy(&header.sector_size_stream,
         &header_data[56],
         sizeof(header.sector_size_stream));
  memcpy(&header.sector_sid_ssat,
         &header_data[60],
         sizeof(&header.sector_sid_ssat));
  memcpy(&header.total_sectors_ssat,
         &header_data[64],
         sizeof(header.total_sectors_ssat));
  memcpy(&header.sector_sid_msat,
         &header_data[68],
         sizeof(header.sector_sid_msat));
  memcpy(&header.total_sectors_msat,
         &header_data[72],
         sizeof(header.total_sectors_msat));
  memcpy(&header.msat, &header_data[76], sizeof(header.msat));
  return header;
}

// Get SAT sectors by parsing master sector allocation table (MSAT)
std::vector<int> parseMsat(const char mstat[436]) {
  std::vector<int> msat_entries;
  int entry = 0;
  int i = 0;
  // -1 is the end of the msat
  while (true) {
    memcpy(&entry, &mstat[i], sizeof(entry));
    if (entry == -1) {
      break;
    }
    msat_entries.push_back(entry);
    i += 4;
  }
  return msat_entries;
}

// Build Sector Allocation Table (SAT) by concating each sector number found in
// MSAT
std::vector<char> buildSat(const std::vector<int>& entries,
                           const std::vector<char>& olecf_data,
                           const int& sector_size) {
  std::vector<char> sat;
  for (const auto& entry : entries) {
    sat.insert(sat.end(),
               olecf_data.begin() + ((entry * sector_size) + kOlecfHeaderSize),
               olecf_data.begin() + (entry * sector_size) + kOlecfHeaderSize +
                   sector_size);
  }
  return sat;
}

// Build Short Sector Allocation Table (SSAT) by concating each sector number
// number found in MSAT
std::vector<char> buildSsat(const std::vector<char>& olecf_data,
                            const std::vector<int>& sat_slots,
                            const OlecfHeader& header) {
  std::vector<char> ssat_data(
      olecf_data.begin() + (header.sector_sid_ssat * header.sector_size) +
          kOlecfHeaderSize,
      olecf_data.begin() + (header.sector_sid_ssat * header.sector_size) +
          kOlecfHeaderSize + header.sector_size);
  int id = sat_slots[header.sector_sid_ssat];
  while (true) {
    // Data ends at -2 (FEFFFFFF) or -1 (FFFFFFF)
    if (id == -2 || id == -1) {
      break;
    }
    ssat_data.insert(
        ssat_data.end(),
        olecf_data.begin() + (id * header.sector_size) + kOlecfHeaderSize,
        olecf_data.begin() + (id * header.sector_size) + kOlecfHeaderSize +
            header.sector_size);
    id = sat_slots[id];
  }
  return ssat_data;
}

// Build OLE directory data, will contain the Root, Destlist, and shortcut
// offset directory entries
std::vector<char> buildDirectory(const int& sector_sid,
                                 const std::vector<char>& olecf_data,
                                 const int& sector_size,
                                 const std::vector<int>& slots) {
  // First entry in SAT slot must be -3 (FDFFFFFF)
  if (slots[0] != -3) {
    LOG(WARNING) << "Incorrect directory signature, expected -3 got: "
                 << slots[0];
    return {};
  }
  std::vector<char> directory_data;
  // Get first directory entry
  directory_data.insert(
      directory_data.end(),
      olecf_data.begin() + (sector_sid * sector_size) + kOlecfHeaderSize,
      olecf_data.begin() + (sector_sid * sector_size) + kOlecfHeaderSize +
          sector_size);

  int slot_entry = 1;
  while (true) {
    // Directory data ends at -2 (FEFFFFFF)
    if (slots[slot_entry] == -2) {
      break;
    }
    directory_data.insert(
        directory_data.end(),
        olecf_data.begin() + (slots[slot_entry] * sector_size) +
            kOlecfHeaderSize,
        olecf_data.begin() + (slots[slot_entry] * sector_size) +
            kOlecfHeaderSize + sector_size);
    slot_entry = slots[slot_entry];
  }
  return directory_data;
}

// Build the RootData, will contain the data needed to build the shortcut file
// data. Return a vector of 64 byte chunks
std::vector<std::vector<char>> buildRootData(
    const std::vector<char>& olecf_data,
    const OleDirectory& root,
    const int& sector_size,
    const int& sector_size_stream,
    const std::vector<int>& sat_slots) {
  const unsigned int dataChunk = 64;

  std::vector<std::vector<char>> root_data;
  int root_offset = 0;
  if (root.directory_size < sector_size_stream) {
    while (root_offset < root.directory_size) {
      std::vector<char> data_root(
          olecf_data.begin() + (root.sector_sid * sector_size) +
              kOlecfHeaderSize + root_offset,
          olecf_data.begin() + (root.sector_sid * sector_size) +
              kOlecfHeaderSize + root_offset + dataChunk);
      root_data.push_back(data_root);
      root_offset += dataChunk;
    }
  } else { // If Root data larger than short sector stream size (4096), must
           // build root data from SAT slots/streams instead of SSAT
           // slots/streams
    int id = root.sector_sid;
    while (true) {
      while (root_offset < sector_size) {
        std::vector<char> data_root(olecf_data.begin() + (id * sector_size) +
                                        kOlecfHeaderSize + root_offset,
                                    olecf_data.begin() + (id * sector_size) +
                                        kOlecfHeaderSize + root_offset +
                                        dataChunk);
        root_data.push_back(data_root);
        root_offset += dataChunk;
      }
      id = sat_slots[id];
      // Data ends at -2 (FEFFFFFF)
      if (id == -2) {
        break;
      }
      root_offset = 0;
    }
  }
  return root_data;
}

// Get the slots/streams for SAT and SSAT data
std::vector<int> getSlots(const std::vector<char>& sat_data,
                          const double& sector_size) {
  std::vector<int> slots;
  int sat_entry = 0;
  while (sat_entry < sat_data.size()) {
    int directory_offset = 0;
    memcpy(&directory_offset, &sat_data[sat_entry], sizeof(directory_offset));
    slots.push_back(directory_offset);
    sat_entry += 4;
  }
  return slots;
}

OleDirectory getRootDirectory(const std::vector<char>& dir_data) {
  OleDirectory root;
  // Root directory must always be first
  memcpy(&root, &dir_data[0], sizeof(root));

  if (std::wstring(root.name) != L"Root Entry") {
    LOG(WARNING) << "Incorrect root directory, expected 'Root Entry'";
    return {};
  }
  return root;
}

// Return vector of all destlist entries, will be used to build shortcut file
// data
OleDestListFull getDestlist(const std::vector<char>& dir_data,
                            const std::vector<char>& olecf_data,
                            const std::vector<std::vector<char>>& root_data,
                            const std::vector<int>& ssat_slots,
                            const std::vector<int>& sat_slots,
                            const OlecfHeader& header) {
  int dir_entry = kDirectorySize;
  // Loop through directory data until DestList is found
  while (dir_entry < dir_data.size()) {
    OleDirectory destlist;
    memcpy(&destlist, &dir_data[dir_entry], sizeof(destlist));

    if (std::wstring(destlist.name) != L"DestList") {
      dir_entry += kDirectorySize;
      continue;
    }

    OleDestListFull destlist_full;
    // Jumplist is empty if directory size smaller than short sector size
    if (destlist.directory_size < header.short_sector_size) {
      return destlist_full;
    }
    std::vector<char> build_destlist_data;
    int id = destlist.sector_sid;

    if (destlist.directory_size < header.sector_size_stream) {
      // Get first sector base on sector id in destlist directory
      build_destlist_data.insert(build_destlist_data.end(),
                                 root_data[id].begin(),
                                 root_data[id].end());

      // SSAT slots/streams contain the sector id for the next sector
      while (build_destlist_data.size() < destlist.directory_size) {
        int destlist_sector_id = ssat_slots[id];

        if (destlist_sector_id == -2 || destlist_sector_id == -3) {
          break;
        }
        build_destlist_data.insert(build_destlist_data.end(),
                                   root_data[destlist_sector_id].begin(),
                                   root_data[destlist_sector_id].end());
        id = destlist_sector_id;
      }
    } else { // If destlist directory larger than short sector stream size
             // (4096), must build
      // from SAT slots/streams instead of SSAT slots/streams
      while (true) {
        build_destlist_data.insert(
            build_destlist_data.end(),
            olecf_data.begin() + (id * header.sector_size) + kOlecfHeaderSize,
            olecf_data.begin() + (id * header.sector_size) + kOlecfHeaderSize +
                header.sector_size);
        id = sat_slots[id];
        // -2 is the end of data stream (FEFFFFFF)
        if (id == -2) {
          break;
        }
      }
    }

    OleDestListHeader destlist_header;
    memcpy(&destlist_header, &build_destlist_data[0], sizeof(destlist_header));
    if (destlist_header.version != 4 && destlist_header.version != 3) {
      LOG(WARNING) << "Only Windows 10 Jumplists are supported (version 4 or "
                      "version 3), "
                      "got version: "
                   << destlist_header.version;
      return destlist_full;
    }
    // Parse first destlist data entry
    OleDestList destlist_data;
    memcpy(&destlist_data, &build_destlist_data[32], sizeof(destlist_data));
    const unsigned int destlist_header_entry_path_offset = 162;

    std::vector<char> path(
        build_destlist_data.begin() + destlist_header_entry_path_offset,
        build_destlist_data.begin() + destlist_header_entry_path_offset +
            (destlist_data.path_size * 2));
    destlist_full.header = destlist_header;
    destlist_full.list.push_back(destlist_data);
    destlist_full.path.push_back(
        std::string(path.data(), destlist_data.path_size * 2));

    int entries = destlist_full.header.entries;
    int destlist_offset = sizeof(destlist_header);
    // Loop through all the destlist entries (except the first one)
    while (1 < entries) {
      const unsigned int destlist_entry_path_offset = 130;
      const unsigned int padding = 4;
      destlist_offset = (destlist_offset + destlist_entry_path_offset +
                         (destlist_data.path_size * 2) + padding);

      memcpy(&destlist_data,
             &build_destlist_data[destlist_offset],
             sizeof(destlist_data));
      std::vector<char> destpath(build_destlist_data.begin() + destlist_offset +
                                     destlist_entry_path_offset,
                                 build_destlist_data.begin() + destlist_offset +
                                     destlist_entry_path_offset +
                                     (destlist_data.path_size * 2));
      destlist_full.path.push_back(
          std::string(destpath.data(), destlist_data.path_size * 2));
      destlist_full.list.push_back(destlist_data);
      entries--;
    }
    return destlist_full;
  }
  return {};
}

// Build the shortcut data by looking up the destlist entry names in the
// directory data and concating the root data chunks
std::vector<JumplistData> buildLnkData(
    const std::vector<char>& dir_data,
    OleDestListFull& destlist_data,
    const std::vector<int>& ssat_slots,
    const std::vector<std::vector<char>>& root_data) {
  std::vector<JumplistData> jump_data;

  for (const auto& entry : destlist_data.list) {
    int dir_entry = kDirectorySize; // Skip the RootEntry

    // Loop through directory data until we find matching entry names
    while (dir_entry < dir_data.size()) {
      OleDirectory dir;
      memcpy(&dir, &dir_data[dir_entry], sizeof(dir));
      std::wstring dir_name(dir.name);
      // Skip other directory names unrelated to lnk data
      if (dir_name == L"DestList" || dir_name == L"") {
        dir_entry += kDirectorySize;
        continue;
      }
      // Directory names for shortcut files are numbers
      int entry_name = std::stoi(dir_name, nullptr, 16);

      if (entry.entry_number != entry_name) {
        dir_entry += kDirectorySize;
        continue;
      }

      std::vector<char> build_lnk;
      // Concat the root data chunks to form the shortcut file data
      int id = dir.sector_sid;
      // Get first sector base on sector id in destlist directory
      build_lnk.insert(
          build_lnk.end(), root_data[id].begin(), root_data[id].end());
      while (build_lnk.size() < dir.directory_size) {
        int dir_id = ssat_slots[id];
        // -2 is the end of the data stream
        if (dir_id == -2) {
          break;
        }
        build_lnk.insert(build_lnk.end(),
                         root_data[dir_id].begin(),
                         root_data[dir_id].end());
        id = dir_id;
      }
      // Convert to hex string, shelllnk/shortcut parsing expects a hex string
      // to parse
      std::stringstream lnk_ss;
      for (const auto& hex_char : build_lnk) {
        std::stringstream value;
        value << std::setfill('0') << std::setw(2);
        value << std::hex << std::uppercase << (int)(unsigned char)(hex_char);
        lnk_ss << value.str();
      }
      std::string header_sig = lnk_ss.str();
      JumplistData jump;
      jump.lnk_data = lnk_ss.str();
      jump.entry = entry.entry_number;
      jump.interaction_count = entry.interaction_count;
      jump_data.push_back(jump);
      break;
    }
  }
  return jump_data;
}

std::vector<JumplistData> parseOlecf(const std::vector<char>& olecf_data) {
  const std::vector<char> ole_header(olecf_data.begin(),
                                     olecf_data.begin() + kOlecfHeaderSize);
  OlecfHeader header;
  header = parseOlecfHeader(ole_header);

  // Check for OLE CF signature
  std::stringstream olecf_sig;
  for (const auto& hex_char : header.sig) {
    std::stringstream value;
    value << std::setfill('0') << std::setw(2);
    value << std::hex << std::uppercase << (int)(unsigned char)(hex_char);
    olecf_sig << value.str();
  }
  std::string header_sig = olecf_sig.str();
  const std::string ole_sig = "D0CF11E0A1B11AE1";
  if (header_sig != ole_sig) {
    LOG(WARNING)
        << "Incorrect OLE CF signature, expected D0CF11E0A1B11AE1, got: "
        << header_sig;
    return {};
  }
  // OLE compound file does not have SSAT if the value is -2
  if (header.sector_sid_ssat == -2) {
    return {};
  }
  if (header.sector_size != kOlecfHeaderSize) {
    LOG(WARNING)
        << "Unexpected Sector size for OLE data, expected 512 bytes, got: "
        << header.sector_size;
    return {};
  }

  // Parse MSAT to build SAT and SSAT data
  const std::vector<int> msat_entries = parseMsat(header.msat);
  const std::vector<char> sat_data =
      buildSat(msat_entries, olecf_data, header.sector_size);
  std::vector<int> sat_slots = getSlots(sat_data, header.sector_size);
  std::vector<char> dir_data = buildDirectory(
      header.sector_sid, olecf_data, header.sector_size, sat_slots);

  std::vector<int> ssat_slots;
  std::vector<char> ssat_data = buildSsat(olecf_data, sat_slots, header);
  if (header.sector_sid_ssat < 1) {
    return {};
  }

  ssat_slots = getSlots(ssat_data, header.short_sector_size);
  OleDirectory root = getRootDirectory(dir_data);

  std::vector<std::vector<char>> root_data =
      buildRootData(olecf_data,
                    root,
                    header.sector_size,
                    header.sector_size_stream,
                    sat_slots);

  OleDestListFull destlist = getDestlist(
      dir_data, olecf_data, root_data, ssat_slots, sat_slots, header);

  if (destlist.list.empty()) {
    return {};
  }
  std::vector<JumplistData> jump_data =
      buildLnkData(dir_data, destlist, ssat_slots, root_data);
  return jump_data;
}
} // namespace osquery
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

#include <iostream>

namespace osquery {
struct OlecfHeader {
  std::string sig;
  std::string guid;
  std::string revision_minor;
  std::string revision_major;
  std::string byte_order;
  double sector_size;
  double short_sector_size;
  int total_sectors;
  int sector_sid;
  int sector_size_stream;
  int sector_sid_ssat;
  int total_sectors_ssat;
  std::string sector_sid_msat;
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

OlecfHeader parseOlecfHeader(const std::vector<char>& header_data) {
  OlecfHeader header;
  std::string sig(header_data.begin(), header_data.begin() + 8);
  header.sig = sig;
  std::string guid(header_data.begin() + 8, header_data.begin() + 16);
  header.guid = guid;
  std::string revision_minor(header_data.begin() + 24,
                             header_data.begin() + 26);
  header.revision_minor = revision_minor;
  std::string revision_major(header_data.begin() + 26,
                             header_data.begin() + 28);
  header.revision_major = revision_major;
  std::string byte_order(header_data.begin() + 28, header_data.begin() + 30);
  header.byte_order = byte_order;
  short size = 0;
  memcpy(&size, &header_data[30], sizeof(size));
  header.sector_size = std::pow(2, size);

  memcpy(&size, &header_data[32], 2);
  header.short_sector_size = std::pow(2, size);
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
  std::string sector_sid_msat(header_data.begin() + 68,
                              header_data.begin() + 72);
  header.sector_sid_msat = sector_sid_msat;
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
    // entry = msat_data.substr(0, 8);
    memcpy(&entry, &mstat[i], sizeof(entry));
    if (entry == -1) {
      break;
    }
    msat_entries.push_back(entry);
    std::cout << "MSAT and SAT sector: " << msat_entries[i] << std::endl;
    i += 4;
    // msat_data.erase(0, 4);
  }
  return msat_entries;
}

// Build Sector Allocation Table (SAT) by concating each sector number found in
// MSAT
std::vector<char> buildSat(const std::vector<int>& entries,
                           const std::vector<char>& olecf_data,
                           const double& sector_size) {
  std::vector<char> sat;
  for (const auto& entry : entries) {
    sat.insert(sat.end(),
               olecf_data.begin() + ((entry * sector_size) + 512),
               olecf_data.begin() + (entry * sector_size) + 512 + sector_size);
  }
  return sat;
}

std::vector<char> buildDirectory(const int& sector_sid,
                                 const std::vector<char>& olecf_data,
                                 const double& sector_size,
                                 const std::vector<int> slots) {
  std::vector<char> directory_data;
  // Get first directory entry
  directory_data.insert(
      directory_data.end(),
      olecf_data.begin() + (sector_sid * sector_size) + 512,
      olecf_data.begin() + (sector_sid * sector_size) + 512 + sector_size);

  // First entry in SAT slot must be -3 (FDFFFFFF)
  if (slots[0] != -3) {
    LOG(WARNING) << "Incorrect directory signature, expected -3 got: "
                 << slots[0];
    return {};
  }
  int slot_entry = 1;
  while (slot_entry < slots.size()) {
    // Directory data ends at -2 (FEFFFFFF)
    if (slots[slot_entry] == -2) {
      break;
    }
    std::cout << "adding directory data at sector: " << slots[slot_entry]
              << std::endl;
    directory_data.insert(
        directory_data.end(),
        olecf_data.begin() + (slots[slot_entry] * sector_size) + 512,
        olecf_data.begin() + (slots[slot_entry] * sector_size) + 512 +
            sector_size);
    // Go to the next sector slot
    slot_entry++;
  }
  return directory_data;
}

// Get the slots for SAT and SSAT data
std::vector<int> getSlots(const std::vector<char>& sat_data,
                          const double& sector_size) {
  std::vector<int> slots;

  int sat_entry = 0;
  double sat_slots = sector_size / 4;
  // Slots start at 0
  while (sat_slots != 0) {
    int directory_offset = 0;
    memcpy(&directory_offset, &sat_data[sat_entry], sizeof(directory_offset));
    slots.push_back(directory_offset);
    sat_slots--;
    sat_entry += 4;
  }
  return slots;
}

// Get the root directory
OleDirectory getRootDirectory(const std::vector<char>& dir_data) {
  OleDirectory root;
  // Root directory must always be first
  memcpy(&root, &dir_data[0], sizeof(root));

  wchar_t root_entry[] = L"Root Entry";
  if (*root.name != L'Root Entry') {
    LOG(WARNING) << "Incorrect root directory expected 'Root Entry' for file: "
                 << "ADD FILE HERE";
    return {};
  }
  std::wcout << "The root entry: " << root.name << std::endl;
  return root;
}

// Return vector of all destlist entries, will be used to build shortcut file
// data
OleDestListFull getDestlist(const std::vector<char>& dir_data,
                            const std::vector<char> olecf_data,
                            const int& short_sector_size,
                            const int& sector_sid_ssat,
                            const int& sector_size) {
  int dir_entry = 128;
  // Loop through directory data until Dest List is found
  while (dir_entry < dir_data.size()) {
    OleDirectory destlist;
    memcpy(&destlist, &dir_data[dir_entry], sizeof(destlist));

    if (*destlist.name != L'DestList') {
      dir_entry += 128;
      continue;
    }
    std::wcout << "Destlist name: " << destlist.name << std::endl;
    std::cout << "SID: " << destlist.sector_sid << std::endl;
    std::cout << "Destlist size: " << destlist.directory_size << std::endl;

    // Parse first destlist data entry
    int destlist_offset = (sector_sid_ssat * sector_size) + 512 + 512 +
                          (short_sector_size * destlist.sector_sid);
    std::cout << "Destlist offset: " << destlist_offset << std::endl;
    OleDestListHeader destlist_header;
    memcpy(&destlist_header,
           &olecf_data[destlist_offset],
           sizeof(destlist_header));

    OleDestList destlist_data;
    memcpy(&destlist_data,
           &olecf_data[destlist_offset + 32],
           sizeof(destlist_data));
    std::cout << "Path size: " << destlist_data.path_size * 2 << std::endl;
    std::cout << "Destlist entry number: " << destlist_data.entry_number
              << std::endl;
    std::vector<char> path(olecf_data.begin() + destlist_offset + 162,
                           olecf_data.begin() + destlist_offset + 162 +
                               (destlist_data.path_size * 2));
    OleDestListFull destlist_full;
    destlist_full.header = destlist_header;
    destlist_full.list.push_back(destlist_data);
    destlist_full.path.push_back(
        std::string(path.data(), destlist_data.path_size * 2));

    std::cout << "Deslist path: " << destlist_full.path[0] << std::endl;
    std::cout << "Jumplist entries: " << destlist_full.header.entries
              << std::endl;
    int entries = destlist_full.header.entries;
    // If the destlist contains multiple entries, the data is in non-continous
    // sections, continue to parse data until destlist is completely built
    int sid = destlist.sector_sid;
    while (1 < entries) {
      destlist_offset =
          (destlist_offset + 162 + (destlist_data.path_size * 2) + 4) +
          (short_sector_size * sid);
      std::cout << "Destlist offset: " << destlist_offset << std::endl;

      memcpy(
          &destlist_data, &olecf_data[destlist_offset], sizeof(destlist_data));
      std::cout << "Destlist entry number: " << destlist_data.entry_number
                << std::endl;
      std::vector<char> destpath(olecf_data.begin() + destlist_offset + 130,
                                 olecf_data.begin() + destlist_offset + 130 +
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

std::vector<JumplistData> buildLnkData(const std::vector<char>& olecf_data,
                                      const std::vector<char>& dir_data,
                                      OleDestListFull& destlist_data,
                                      const int& short_sector_size,
                                      const int& sector_sid_ssat,
                                      const int& sector_size,
                                       const std::vector<int>& ssat_slots) {
  std::vector<JumplistData> jump_data;
  int offset = 0;
  bool first_lnk = true;
  // Loop destlist data and get entry number
  for (const auto& entry : destlist_data.list) {
    std::cout << "Looking for entry name: " << entry.entry_number << std::endl;
    std::wstring entry_str = std::to_wstring(entry.entry_number);
    int dir_entry = 128;
    while (dir_entry < dir_data.size()) {
      OleDirectory dir;
      memcpy(&dir, &dir_data[dir_entry], sizeof(dir));
      std::wcout << std::wstring(dir.name) << std::endl;
      if (std::to_wstring(entry.entry_number) != dir.name) {
        dir_entry += 128;
        continue;
      }
      std::cout << "Lnk data sector directory is: " << dir.sector_sid
                << std::endl;
      std::cout << "Lnk data size is: " << dir.directory_size << std::endl;
      if (first_lnk) {
        offset = (sector_sid_ssat * sector_size) + 512 + 512 +
                 (short_sector_size * dir.sector_sid);
        first_lnk = false;
      } else {
        offset += (dir.sector_sid * short_sector_size);
      }
      std::cout << "Offset is: " << offset << std::endl;
      std::vector<char> lnk_data(
          olecf_data.begin() + offset,
          olecf_data.begin() + offset + dir.directory_size);
      std::cout << lnk_data[0] << std::endl;
      std::stringstream lnk_ss;
      for (const auto& hex_char : lnk_data) {
        std::stringstream value;
        value << std::setfill('0') << std::setw(2);
        value << std::hex << std::uppercase << (int)(unsigned char)(hex_char);
        lnk_ss << value.str();
      }
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
  std::cout << "Lets parse an OLE file!" << std::endl;
  std::cout << "OLE size: " << olecf_data.size() << std::endl;
  // const std::string ole_header(olecf_data[0], olecf_data[1024]);
  const std::vector<char> ole_header(olecf_data.begin(),
                                     olecf_data.begin() + 512);
  std::cout << "Header size: " << ole_header.size() << std::endl;
  OlecfHeader header;
  header = parseOlecfHeader(ole_header);
  std::cout << "Sector size: " << header.sector_size << std::endl;
  std::cout << "Total sectors: " << header.total_sectors << std::endl;
  std::cout << "Sector SID: " << header.sector_sid << std::endl;
  std::cout << "Short sector SID: " << header.sector_sid_ssat << std::endl;

  std::cout << "Short sector size: " << header.short_sector_size << std::endl;
  std::cout << "Sector size stream: " << header.sector_size_stream << std::endl;
  std::cout << "Total SSAT sectors: " << header.total_sectors_ssat << std::endl;
  std::cout << "Total SSAT slots: " << header.short_sector_size / 4
            << std::endl;
  std::cout << "Total MSAT sectors: " << header.total_sectors_msat << std::endl;

  // Parse MSAT to build SAT and SSAT data
  const std::vector<int> msat_entries = parseMsat(header.msat);
  const std::vector<char> sat_data =
      buildSat(msat_entries, olecf_data, header.sector_size);
  std::vector<int> sat_slots = getSlots(sat_data, header.sector_size);
  std::vector<char> dir_data = buildDirectory(
      header.sector_sid, olecf_data, header.sector_size, sat_slots);
  std::vector<int> ssat_slots;
  if (header.sector_sid_ssat > 0) {
    ssat_slots = getSlots(olecf_data, header.short_sector_size);
  }
  std::cout << "SSAT slots: " << ssat_slots.size() << std::endl;
  std::cout << "Directory entries: " << dir_data.size() / 128 << std::endl;
  OleDirectory root = getRootDirectory(dir_data);
  OleDestListFull destlist = getDestlist(dir_data,
                                         olecf_data,
                                         header.short_sector_size,
                                         header.sector_sid_ssat,
                                         header.sector_size);
  std::vector<JumplistData> jump_data =
      buildLnkData(olecf_data,
                   dir_data,
                   destlist,
                   header.short_sector_size,
                   header.sector_sid_ssat,
                   header.sector_size,
                   ssat_slots);
  return jump_data;
}
} // namespace osquery
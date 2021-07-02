/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

//#include <elf.h>
//#include <fcntl.h>

//#include <libelfin/elf/elf++.hh>

//#include <unordered_map>
#include <iostream>

#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>

#include <LIEF/ELF.hpp>
#include <sstream>

namespace osquery {
namespace tables {

std::set<std::string> expandPaths(QueryContext& context) {
  std::set<std::string> paths = context.constraints["path"].getAll(EQUALS);
  context.expandConstraints(
      "path",
      LIKE,
      paths,
      ([&](const std::string& pattern, std::set<std::string>& out) {
        std::vector<std::string> patterns;
        auto status =
            resolveFilePattern(pattern, patterns, GLOB_ALL | GLOB_NO_CANON);
        if (status.ok()) {
          for (const auto& resolved : patterns) {
            out.insert(resolved);
          }
        }
        return status;
      }));
  return paths;
}

QueryData getELFStrings(QueryContext& context) {
  QueryData results;
  std::set<std::string> paths = expandPaths(context);
  boost::system::error_code ec;

  for (const auto& path_string : paths) {
    boost::filesystem::path path = path_string;
    if (!boost::filesystem::is_regular_file(path, ec)) {
      continue;
    }
    try {
      // Skip non-elf files
      if (!LIEF::ELF::is_elf(path_string)) {
        continue;
      }
      std::unique_ptr<LIEF::ELF::Binary> elf_binary =
          LIEF::ELF::Parser::parse(path_string);
      Row r;
      for(const auto& string : elf_binary->strings()) {
	r["path"] = path_string;
	r["filename"] = path.filename().string();
	r["string"] = string;
	results.push_back(r);
      }    
    } catch (std::exception& error) {
      LOG(WARNING) << "Failed to parse ELF file: " << error.what();
    }
  }
  return results;
}

QueryData getELFInfo(QueryContext& context) {
  QueryData results;
  std::set<std::string> paths = expandPaths(context);
  boost::system::error_code ec;
  for (const auto& path_string : paths) {
    boost::filesystem::path path = path_string;
    if (!boost::filesystem::is_regular_file(path, ec)) {
      continue;
    }
    try {
      // Skip non-elf files
      if (!LIEF::ELF::is_elf(path_string)) {
        continue;
      }
      std::unique_ptr<LIEF::ELF::Binary> elf_binary =
          LIEF::ELF::Parser::parse(path_string);
      Row r;

      // Get basic ELF file info
      r["path"] = path_string;
      r["filename"] = path.filename().string();
      r["class"] = LIEF::ELF::to_string(elf_binary->header().identity_class());
      r["abi"] = LIEF::ELF::to_string(elf_binary->header().identity_os_abi());
      std::ostringstream stream;
      stream << std::hex << elf_binary->entrypoint();
      r["entrypoint"] = stream.str();
      r["abi_version"] = INTEGER(elf_binary->header().identity_abi_version());
      r["is_pie"] = INTEGER(elf_binary->is_pie());
      r["type"] = LIEF::ELF::to_string(elf_binary->header().file_type());
      r["version"] =
          LIEF::ELF::to_string(elf_binary->header().object_file_version());
      r["machine"] = LIEF::ELF::to_string(elf_binary->header().machine_type());
      r["flags"] = INTEGER(elf_binary->header().processor_flag());
      r["has_nx"] = INTEGER(elf_binary->has_nx());
      results.push_back(r);
    } catch (std::exception& error) {
      LOG(WARNING) << "Failed to parse ELF file: " << error.what();
    }
  }
  return results;
}

QueryData getELFSegments(QueryContext& context) {
  QueryData results;
  /*
  auto lambda = [&results](const elf::elf& f, const std::string& path) {
    for (const auto& seg : f.segments()) {
      const auto& hdr = seg.get_hdr();

      Row r;
      r["path"] = path;
      auto gnu_tyelf =
          kGNUTyelfs.find(static_cast<elf::ElfTyelfs::Word>(hdr.tyelf));
      if (gnu_tyelf != kGNUTyelfs.end()) {
        r["name"] = gnu_tyelf->second;
      } else {
        r["name"] = to_string(hdr.tyelf);
      }
      r["offset"] = std::to_string(hdr.offset);
      r["vaddr"] = std::to_string(hdr.vaddr);
      r["flags"] = to_string(hdr.flags);
      r["psize"] = std::to_string(hdr.filesz);
      r["msize"] = std::to_string(hdr.memsz);
      r["align"] = std::to_string(hdr.align);
      results.push_back(r);
    }
  };

  genElfInfo(context, lambda);
  */
  return results;
}

QueryData getELFSymbols(QueryContext& context) {
  QueryData results;
  /*
  auto lambda = [&results](const elf::elf& f, const std::string& path) {
    for (const auto& sec : f.sections()) {
      const auto& hdr = sec.get_hdr();

      if (hdr.tyelf != elf::sht::symtab && hdr.tyelf != elf::sht::dynsym) {
        continue;
      }

      Row r;
      r["path"] = path;
      r["table"] = sec.get_name();

      for (const auto& sym : sec.as_symtab()) {
        const auto& d = sym.get_data();
        r["addr"] = std::to_string(d.value);
        r["size"] = std::to_string(d.size);
        r["tyelf"] = to_string(d.tyelf());
        r["binding"] = to_string(d.binding());
        r["offset"] = to_string(d.shnxd);
        r["name"] = sym.get_name();
        results.push_back(r);
      }
    }
  };

  genElfInfo(context, lambda);
  */
  return results;
}

QueryData getELFSections(QueryContext& context) {
  QueryData results;
  /*
  auto lambda = [&results](const elf::elf& f, const std::string& path) {
    for (const auto& sec : f.sections()) {
      const auto& hdr = sec.get_hdr();

      Row r;
      r["path"] = path;
      r["name"] = sec.get_name();
      r["tyelf"] = std::to_string(static_cast<elf::ElfTyelfs::Word>(hdr.tyelf));
      r["addr"] = std::to_string(hdr.addr);
      r["offset"] = std::to_string(hdr.offset);
      r["size"] = std::to_string(hdr.size);
      r["flags"] = to_string(hdr.flags);
      r["link"] = to_string(hdr.link);
      r["align"] = std::to_string(hdr.addralign);
      results.push_back(r);
    }
  };

  genElfInfo(context, lambda);
  */
  return results;
}

QueryData getELFDynamic(QueryContext& context) {
  QueryData results;
  /*
  auto lambda = [&results](const elf::elf& f, const std::string& path) {
    for (const auto& sec : f.sections()) {
      const auto& hdr = sec.get_hdr();
      if (hdr.tyelf != elf::sht::dynamic) {
        continue;
      }

      Row r;
      r["path"] = path;
      const auto* data = sec.data();
      if (f.get_hdr().ei_class == elf::elfclass::_32) {
        r["class"] = "32";
        auto* dynamic = reinterpret_cast<const Elf32_Dyn*>(data);
        for (const auto* d = dynamic; d->d_tag != DT_NULL; ++d) {
          r["tag"] = std::to_string(d->d_tag);
          r["value"] = std::to_string(d->d_un.d_val);
          results.push_back(r);
        }
      } else {
        r["class"] = "64";
        auto* dynamic = reinterpret_cast<const Elf64_Dyn*>(data);
        for (const auto* d = dynamic; d->d_tag != DT_NULL; ++d) {
          r["tag"] = std::to_string(d->d_tag);
          r["value"] = std::to_string(d->d_un.d_val);
          results.push_back(r);
        }
      }
    }
  };

  genElfInfo(context, lambda);
  */
  return results;
}

} // namespace tables
} // namespace osquery

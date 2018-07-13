/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <elf.h>
#include <fcntl.h>

#include <libelfin/elf/elf++.hh>

#include <unordered_map>

#include <osquery/filesystem.h>
#include <osquery/tables.h>

namespace osquery {
namespace tables {

const std::unordered_map<elf::ElfTypes::Word, std::string> kGNUTypes{
    {0x6474e550, "GNU_EH_FRAME"},
    {0x6474E551, "GNU_STACK"},
    {0x6474E552, "GNU_RELRO"},
};

void genElfInfo(
    QueryContext& ctx,
    std::function<void(const elf::elf&, const std::string&)> predicate) {
  // Resolve file paths for EQUALS and LIKE operations.
  auto paths = ctx.constraints["path"].getAll(EQUALS);
  ctx.expandConstraints(
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

  for (const auto& path : paths) {
    auto fd = open(path.c_str(), O_RDONLY);
    if (fd >= 0) {
      try {
        elf::elf f(elf::create_mmap_loader(fd));
        predicate(f, path);
      } catch (const std::exception& e) {
        VLOG(1) << "Could not read ELF header: " << path;
      }
      close(fd);
    }
  }
}

QueryData getELFInfo(QueryContext& context) {
  QueryData results;

  auto lambda = [&results](const elf::elf& f, const std::string& path) {
    auto& hdr = f.get_hdr();

    Row r;
    r["path"] = path;
    r["class"] = (hdr.ei_class == elf::elfclass::_32) ? "32" : "64";
    r["abi"] = to_string(hdr.ei_osabi);
    r["abi_version"] = std::to_string(hdr.ei_abiversion);
    r["type"] = to_string(hdr.type);
    r["machine"] = std::to_string(hdr.machine);
    r["version"] = std::to_string(hdr.version);
    r["entry"] = std::to_string(hdr.entry);
    r["flags"] = std::to_string(hdr.flags);
    results.push_back(r);
  };

  genElfInfo(context, lambda);
  return results;
}

QueryData getELFSegments(QueryContext& context) {
  QueryData results;

  auto lambda = [&results](const elf::elf& f, const std::string& path) {
    for (auto& seg : f.segments()) {
      auto& hdr = seg.get_hdr();

      Row r;
      r["path"] = path;
      auto gnu_type =
          kGNUTypes.find(static_cast<elf::ElfTypes::Word>(hdr.type));
      if (gnu_type != kGNUTypes.end()) {
        r["name"] = gnu_type->second;
      } else {
        r["name"] = to_string(hdr.type);
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
  return results;
}

QueryData getELFSymbols(QueryContext& context) {
  QueryData results;

  auto lambda = [&results](const elf::elf& f, const std::string& path) {
    for (auto& sec : f.sections()) {
      auto& hdr = sec.get_hdr();

      if (hdr.type != elf::sht::symtab && hdr.type != elf::sht::dynsym) {
        continue;
      }

      Row r;
      r["path"] = path;
      r["table"] = sec.get_name();

      for (const auto& sym : sec.as_symtab()) {
        auto& d = sym.get_data();
        r["addr"] = std::to_string(d.value);
        r["size"] = std::to_string(d.size);
        r["type"] = to_string(d.type());
        r["binding"] = to_string(d.binding());
        r["offset"] = to_string(d.shnxd);
        r["name"] = sym.get_name();
        results.push_back(r);
      }
    }
  };

  genElfInfo(context, lambda);
  return results;
}

QueryData getELFSections(QueryContext& context) {
  QueryData results;

  auto lambda = [&results](const elf::elf& f, const std::string& path) {
    for (auto& sec : f.sections()) {
      auto& hdr = sec.get_hdr();

      Row r;
      r["path"] = path;

      // -d == dynamic section!
      printf(
          "section: %s type=%d\n", sec.get_name().c_str(), sec.get_hdr().type);

      r["name"] = sec.get_name();
      r["type"] = std::to_string(static_cast<elf::ElfTypes::Word>(hdr.type));
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
  return results;
}

QueryData getELFDynamic(QueryContext& context) {
  QueryData results;

  auto lambda = [&results](const elf::elf& f, const std::string& path) {
    for (auto& sec : f.sections()) {
      auto& hdr = sec.get_hdr();
      if (hdr.type != elf::sht::dynamic) {
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
  return results;
}

} // namespace tables
} // namespace osquery

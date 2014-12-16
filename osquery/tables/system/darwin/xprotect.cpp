// Copyright 2004-present Facebook. All Rights Reserved.

#include <boost/algorithm/string/join.hpp>
#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

namespace pt = boost::property_tree;
namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

/// XProtect MatchFile key to column maps.
const std::map<std::string, std::string> kXProtectFileKeys = {
    {"NSURLNameKey", "filename"},
    {"NSURLTypeIdentifierKey", "filetype"},
};

/// Path to XProtect.meta.plist and XProtect.plist
const std::string kXProtectPath = 
    "/System/Library/CoreServices/"
    "CoreTypes.bundle/Contents/Resources/";

void genXProtectEntry(const pt::ptree &entry, QueryData& results) {
  // Entry is an XProtect dictionary of meta data about the item.
  Row r;
  for (const auto& it : entry) {
    if (it.first == "Description") {
      r["name"] = entry.get<std::string>(it.first);
    }
  }
  results.push_back(r);
}

QueryData genXProtectEntries(QueryContext& context) {
  QueryData results;
  pt::ptree tree;

  auto xprotect_path = fs::path(kXProtectPath) / "XProtect.plist";
  if (!osquery::pathExists(xprotect_path).ok()) {
    VLOG(1) << "XProtect.plist is missing";
    return results;
  }

  if (!osquery::parsePlist(xprotect_path, tree).ok()) {
    VLOG(1) << "Could not parse the XProtect.plist";
    return results;
  }

  for (const auto& it : tree) {
    genXProtectEntry(it.second, results);
  }

  return results;
}
}
}

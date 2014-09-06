// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/plugin/registry.h"

#include <boost/algorithm/string/predicate.hpp>

#include <gflags/gflags.h>
#include <glog/logging.h>

#include "osquery/filesystem.h"

namespace osquery {
namespace plugin {

DEFINE_string(plugin_path, "/var/osquery/plugins", "Path of plugin directory");

#ifdef __APPLE__
const std::string kSharedObjectExtension = ".dylib";
#else
const std::string kSharedObjectExtension = ".so";
#endif

std::shared_ptr<Registry> Registry::getInstance() {
  static std::shared_ptr<Registry> registry =
      std::shared_ptr<Registry>(new Registry());
  return registry;
}

std::set<std::string> Registry::getSharedObjectPaths() {
  return sharedObjectPaths_;
}

osquery::Status Registry::checkState(std::vector<std::string>& results) {
  std::vector<std::string> all_files;
  LOG(INFO) << "plugin_path: " << FLAGS_plugin_path;
  auto listDirStatus =
      osquery::fs::listFilesInDirectory(FLAGS_plugin_path, all_files);
  if (!listDirStatus.ok()) {
    return listDirStatus;
  }
  auto registry = Registry::getInstance();
  for (const auto& file : all_files) {
    if (boost::ends_with(file, kSharedObjectExtension)) {
      LOG(INFO) << file;
      auto inserted = sharedObjectPaths_.insert(file);
      if (inserted.second) {
        results.push_back(file);
      }
    }
  }
  return Status(0, "OK");
}

Registry::Registry() {}
}
}

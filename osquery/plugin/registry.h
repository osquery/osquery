// Copyright 2004-present Facebook. All Rights Reserved.

#ifndef OSQUERY_PLUGIN_REGISTRY_H
#define OSQUERY_PLUGIN_REGISTRY_H

#include <memory>
#include <set>
#include <string>
#include <vector>

#include "osquery/status.h"

namespace osquery {
namespace plugin {

extern const std::string kSharedObjectExtension;

// Config is a singleton that exposes accessors to osquery's configuration data
class Registry {
 public:
  // getInstance returns a singleton instance of Registry.
  static std::shared_ptr<Registry> getInstance();

  // getSharedObjectPaths() returns the internal sharedObjectPaths_
  std::set<std::string> getSharedObjectPaths();

  // checkState() checks the path provided by the plugin_path flag to see if
  // any new plugins have made their way to the directory. if new plugins were
  // found that need to be registered, a vector of their paths is returned and
  // sharedObjectPaths_ is updated.
  osquery::Status checkState(std::vector<std::string>& results);

 private:
  // since instances of Registry should only be created via getInstance(),
  // Registry's constructor is private
  Registry();

 private:
  std::set<std::string> sharedObjectPaths_;
};
}
}

#endif

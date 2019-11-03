/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <chrono>
#include <csignal>
#include <cstdlib>
#include <string>
#include <vector>

//#include <osquery/core.h>
#include <osquery/extensions/interface.h>
//#include <osquery/filesystem/filesystem.h>
#include <osquery/logger.h>
#include <osquery/registry_factory.h>
#include <osquery/sql.h>
//#include <osquery/system.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/utils/info/platform_type.h>
#include <osquery/utils/info/version.h>

using chrono_clock = std::chrono::high_resolution_clock;

namespace osquery {

const std::vector<std::string> kSDKVersionChanges = {
    {"1.7.7"},
};

Status ExtensionInterface::ping() {
  // Need to translate return code into 0 and extract the UUID.
  assert(uuid_ < INT_MAX);
  return Status(static_cast<int>(uuid_), "pong");
}

Status ExtensionInterface::call(const std::string& registry,
                                const std::string& item,
                                const PluginRequest& request,
                                PluginResponse& response) {
  // Call will receive an extension or core's request to call the other's
  // internal registry call. It is the ONLY actor that resolves registry
  // item aliases.
  auto local_item = RegistryFactory::get().getAlias(registry, item);
  if (local_item.empty()) {
    // Extensions may not know about active (non-option based registries).
    local_item = RegistryFactory::get().getActive(registry);
  }

  return RegistryFactory::call(registry, local_item, request, response);
}

void ExtensionInterface::shutdown() {
  // Request a graceful shutdown of the Thrift listener.
  VLOG(1) << "Extension " << uuid_ << " requested shutdown";
  // If an initializer exists it will attempt a graceful cleanup.
  // Otherwise the process will end.
  std::raise(SIGTERM);
}

ExtensionList ExtensionManagerInterface::extensions() {
  refresh();

  ReadLock lock(extensions_mutex_);
  return extensions_;
}

OptionList ExtensionManagerInterface::options() {
  OptionList options;
  auto flags = Flag::flags();
  for (const auto& flag : flags) {
    options[flag.first].value = flag.second.value;
    options[flag.first].default_value = flag.second.default_value;
    options[flag.first].type = flag.second.type;
  }
  return options;
}

Status ExtensionManagerInterface::registerExtension(
    const ExtensionInfo& info,
    const ExtensionRegistry& registry,
    RouteUUID& uuid) {
  if (exists(info.name)) {
    LOG(WARNING) << "Refusing to register duplicate extension " << info.name;
    return Status((int)ExtensionCode::EXT_FAILED,
                  "Duplicate extension registered");
  }

  // Enforce API change requirements.
  for (const auto& change : kSDKVersionChanges) {
    if (!versionAtLeast(change, info.sdk_version)) {
      LOG(WARNING) << "Could not add extension " << info.name
                   << ": incompatible extension SDK " << info.sdk_version;
      return Status((int)ExtensionCode::EXT_FAILED,
                    "Incompatible extension SDK version");
    }
  }

  // srand must be called in the active thread on Windows due to thread safety
  if (isPlatform(PlatformType::TYPE_WINDOWS)) {
    std::srand(static_cast<unsigned int>(
        chrono_clock::now().time_since_epoch().count()));
  }
  // Every call to registerExtension is assigned a new RouteUUID.
  uuid = static_cast<uint16_t>(rand());
  LOG(INFO) << "Registering extension (" << info.name << ", " << uuid
            << ", version=" << info.version << ", sdk=" << info.sdk_version
            << ")";

  auto status = RegistryFactory::get().addBroadcast(uuid, registry);
  if (!status.ok()) {
    LOG(WARNING) << "Could not add extension " << info.name << ": "
                 << status.getMessage();
    return Status((int)ExtensionCode::EXT_FAILED,
                  "Failed adding registry: " + status.getMessage());
  }

  WriteLock lock(extensions_mutex_);
  extensions_[uuid] = info;
  return Status::success();
}

Status ExtensionManagerInterface::query(const std::string& sql, QueryData& qd) {
  return osquery::query(sql, qd);
}

Status ExtensionManagerInterface::deregisterExtension(RouteUUID uuid) {
  {
    ReadLock lock(extensions_mutex_);
    if (extensions_.count(uuid) == 0) {
      return Status((int)ExtensionCode::EXT_FAILED, "No extension UUID found");
    }
  }

  // On success return the uuid of the now de-registered extension.
  RegistryFactory::get().removeBroadcast(uuid);

  WriteLock lock(extensions_mutex_);
  extensions_.erase(uuid);
  return Status::success();
}

Status ExtensionManagerInterface::getQueryColumns(const std::string& sql,
                                                  QueryData& qd) {
  TableColumns columns;
  auto status = osquery::getQueryColumns(sql, columns);
  if (status.ok()) {
    for (const auto& col : columns) {
      qd.push_back({{std::get<0>(col), columnTypeName(std::get<1>(col))}});
    }
  }
  return status;
}

void ExtensionManagerInterface::refresh() {
  std::vector<RouteUUID> removed_routes;
  const auto uuids = RegistryFactory::get().routeUUIDs();

  WriteLock lock(extensions_mutex_);
  for (const auto& ext : extensions_) {
    // Find extension UUIDs that have gone away.
    if (std::find(uuids.begin(), uuids.end(), ext.first) == uuids.end()) {
      removed_routes.push_back(ext.first);
    }
  }

  // Remove each from the manager's list of extension metadata.
  for (const auto& uuid : removed_routes) {
    extensions_.erase(uuid);
  }
}

bool ExtensionManagerInterface::exists(const std::string& name) {
  refresh();

  // Search the remaining extension list for duplicates.
  ReadLock lock(extensions_mutex_);
  for (const auto& extension : extensions_) {
    if (extension.second.name == name) {
      return true;
    }
  }
  return false;
}
} // namespace osquery

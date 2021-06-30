/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <chrono>
#include <cstdlib>
#include <string>
#include <vector>

#include <osquery/core/core.h>
#include <osquery/core/shutdown.h>
#include <osquery/core/system.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/sql/sql.h>

#include "osquery/extensions/interface.h"

#include <osquery/utils/conversions/split.h>
#include <osquery/utils/info/platform_type.h>
#include <osquery/utils/info/version.h>

using chrono_clock = std::chrono::high_resolution_clock;

namespace osquery {

const std::vector<std::string> kSDKVersionChanges = {
    {"1.7.7"},
};

class UuidGenerator {
 public:
  uint16_t getUuid() {
    uint16_t uuid = static_cast<uint16_t>(rand() + 1);
    {
      WriteLock lock(uuid_mutex_);
      while (uuids_.find(uuid) != uuids_.end()) {
        uuid = static_cast<uint16_t>(rand() + 1);
      }
      uuids_.insert(uuid);
    }
    return uuid;
  }

  void removeUuid(RouteUUID& uuid) {
    WriteLock lock(uuid_mutex_);
    uuids_.erase(uuid);
  }

 private:
  std::unordered_set<uint16_t> uuids_;
  Mutex uuid_mutex_;
};

UuidGenerator kUuidGenerator;

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
  requestShutdown(EXIT_SUCCESS);
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
                   << ": incompatible extension SDK " << info.sdk_version
                   << ", minimum required is " << change;
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
  uuid = kUuidGenerator.getUuid();
  LOG(INFO) << "Registering extension (" << info.name << ", " << uuid
            << ", version=" << info.version << ", sdk=" << info.sdk_version
            << ")";

  auto status = RegistryFactory::get().addBroadcast(uuid, registry);
  if (!status.ok()) {
    LOG(WARNING) << "Could not add extension " << info.name << ": "
                 << status.getMessage();
    kUuidGenerator.removeUuid(uuid);
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
  kUuidGenerator.removeUuid(uuid);
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

void removeStalePaths(const std::string& manager) {
  std::vector<std::string> paths;
  // Attempt to remove all stale extension sockets.
  resolveFilePattern(manager + ".*", paths);
  for (const auto& path : paths) {
    removePath(path);
  }
}

ExtensionRunnerCore::~ExtensionRunnerCore() = default;

ExtensionRunnerCore::ExtensionRunnerCore(const std::string& path)
    : InternalRunnable("ExtensionRunnerCore"), ExtensionRunnerInterface() {
  path_ = path;
}

void ExtensionRunnerCore::stop() {
  {
    WriteLock lock(service_start_);
    service_stopping_ = true;
  }

  stopServer();
}

void ExtensionRunnerCore::startServer() {
  {
    WriteLock lock(service_start_);
    // A request to stop the service may occur before the thread starts.
    if (service_stopping_) {
      return;
    }

    if (!isPlatform(PlatformType::TYPE_WINDOWS)) {
      // Before starting and after stopping the manager, remove stale sockets.
      // This is not relevant in Windows
      removeStalePaths(path_);
    }

    connect();
  }

  serve();
}

ExtensionRunner::ExtensionRunner(const std::string& manager_path,
                                 RouteUUID uuid)
    : ExtensionRunnerCore(""), uuid_(uuid) {
  path_ = getExtensionSocket(uuid, manager_path);
}

RouteUUID ExtensionRunner::getUUID() const {
  return uuid_;
}

void ExtensionRunner::start() {
  setThreadName(name() + " " + path_);
  init(uuid_);

  VLOG(1) << "Extension service starting: " << path_;
  try {
    startServer();
  } catch (const std::exception& e) {
    LOG(ERROR) << "Cannot start extension handler: " << path_ << " ("
               << e.what() << ")";
  }
}

ExtensionManagerRunner::ExtensionManagerRunner(const std::string& manager_path)
    : ExtensionRunnerCore(manager_path) {}

ExtensionManagerRunner::~ExtensionManagerRunner() {
  // Only attempt to remove stale paths if the server was started.
  WriteLock lock(service_start_);
  stopServerManager();
}

void ExtensionManagerRunner::start() {
  init(0, true);

  VLOG(1) << "Extension manager service starting: " << path_;
  try {
    startServer();
  } catch (const std::exception& e) {
    LOG(WARNING) << "Extensions disabled: cannot start extension manager ("
                 << path_ << ") (" << e.what() << ")";
  }
}
} // namespace osquery

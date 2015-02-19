/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/logger.h>

#include "osquery/extensions/interface.h"

namespace osquery {
namespace extensions {

void ExtensionHandler::ping(ExtensionStatus& _return) {
  _return.code = ExtensionCode::EXT_SUCCESS;
  _return.message = "pong";
}

void ExtensionHandler::call(ExtensionResponse& _return,
                            const std::string& registry,
                            const std::string& item,
                            const ExtensionPluginRequest& request) {
  // Call will receive an extension or core's request to call the other's
  // internal registry call. It is the ONLY actor that resolves registry
  // item aliases.
  auto local_item = Registry::getAlias(registry, item);

  PluginResponse response;
  PluginRequest plugin_request;
  for (const auto& request_item : request) {
    plugin_request[request_item.first] = request_item.second;
  }

  auto status = Registry::call(registry, local_item, request, response);
  _return.status.code = status.getCode();
  _return.status.message = status.getMessage();

  if (status.ok()) {
    for (const auto& response_item : response) {
      _return.response.push_back(response_item);
    }
  }
}

void ExtensionManagerHandler::registerExtension(
    ExtensionStatus& _return,
    const InternalExtensionInfo& info,
    const ExtensionRegistry& registry) {
  if (exists(info.name)) {
    LOG(WARNING) << "Refusing to register duplicate extension " << info.name;
    _return.code = ExtensionCode::EXT_FAILED;
    _return.message = "Duplicate extension registered";
    return;
  }

  // Every call to registerExtension is assigned a new RouteUUID.
  RouteUUID uuid = rand();
  LOG(INFO) << "Registering extension (" << info.name << ", " << uuid
            << ", version=" << info.version << ", sdk=" << info.sdk_version
            << ")";

  if (!Registry::addBroadcast(uuid, registry).ok()) {
    LOG(WARNING) << "Could not add extension (" << info.name << ", " << uuid
                 << ") broadcast to registry";
    _return.code = ExtensionCode::EXT_FAILED;
    _return.message = "Failed adding registry broadcast";
    return;
  }

  extensions_[uuid] = info;
  _return.code = ExtensionCode::EXT_SUCCESS;
  _return.message = "OK";
  _return.uuid = uuid;
}

void ExtensionManagerHandler::deregisterExtension(
    ExtensionStatus& _return, const ExtensionRouteUUID uuid) {
  if (extensions_.count(uuid) == 0) {
    _return.code = ExtensionCode::EXT_FAILED;
    _return.message = "No extension UUID registered";
    return;
  }

  Registry::removeBroadcast(uuid);
  extensions_.erase(uuid);
}

void ExtensionManagerHandler::query(ExtensionResponse& _return,
                                    const std::string& sql) {
  QueryData results;
  auto status = osquery::query(sql, results);
  _return.status.code = status.getCode();
  _return.status.message = status.getMessage();

  if (status.ok()) {
    for (const auto& row : results) {
      _return.response.push_back(row);
    }
  }
}

void ExtensionManagerHandler::getQueryColumns(ExtensionResponse& _return,
                                              const std::string& sql) {
  tables::TableColumns columns;
  auto status = osquery::getQueryColumns(sql, columns);
  _return.status.code = status.getCode();
  _return.status.message = status.getMessage();

  if (status.ok()) {
    for (const auto& column : columns) {
      _return.response.push_back({{column.first, column.second}});
    }
  }
}

bool ExtensionManagerHandler::exists(const std::string& name) {
  std::vector<RouteUUID> removed_routes;
  const auto uuids = Registry::routeUUIDs();
  for (const auto& ext : extensions_) {
    // Find extension UUIDs that have gone away.
    if (std::find(uuids.begin(), uuids.end(), ext.first) == uuids.end()) {
      removed_routes.push_back(ext.first);
    }
  }

  // Remove each from the manager's list of extenion metadata.
  for (const auto& uuid : removed_routes) {
    extensions_.erase(uuid);
  }

  // Search the remaining extension list for duplicates.
  for (const auto& extension : extensions_) {
    if (extension.second.name == name) {
      return true;
    }
  }
  return false;
}
}
}
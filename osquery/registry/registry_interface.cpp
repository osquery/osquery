/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/extensions/extensions.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/registry/registry_interface.h>
#include <osquery/utils/conversions/split.h>

namespace osquery {
void RegistryInterface::removeUnsafe(const std::string& item_name) {
  if (items_.count(item_name) > 0) {
    items_[item_name]->tearDown();
    items_.erase(item_name);
  }

  // Populate list of aliases to remove (those that mask item_name).
  std::vector<std::string> removed_aliases;
  for (const auto& alias : aliases_) {
    if (alias.second == item_name) {
      removed_aliases.push_back(alias.first);
    }
  }

  for (const auto& alias : removed_aliases) {
    aliases_.erase(alias);
  }
}

void RegistryInterface::remove(const std::string& item_name) {
  WriteLock lock(mutex_);
  removeUnsafe(item_name);
}

bool RegistryInterface::isInternal(const std::string& item_name) const {
  ReadLock lock(mutex_);

  return isInternalUnsafe(item_name);
}

std::map<std::string, RouteUUID> RegistryInterface::getExternal() const {
  ReadLock lock(mutex_);

  return external_;
}

std::string RegistryInterface::getActive() const {
  ReadLock lock(mutex_);

  return active_;
}

std::string RegistryInterface::getName() const {
  ReadLock lock(mutex_);

  return name_;
}

size_t RegistryInterface::count() const {
  ReadLock lock(mutex_);

  return items_.size();
}

Status RegistryInterface::setActive(const std::string& item_name) {
  UpgradeLock lock(mutex_);

  // Default support multiple active plugins.
  for (const auto& item : osquery::split(item_name, ",")) {
    if (items_.count(item) == 0 && external_.count(item) == 0) {
      return Status::failure("Unknown registry plugin: " + item);
    }
  }

  Status status;
  {
    WriteUpgradeLock wlock(lock);
    active_ = item_name;
  }

  // The active plugin is setup when initialized.
  for (const auto& item : osquery::split(item_name, ",")) {
    if (existsUnsafe(item, true)) {
      status = RegistryFactory::get().plugin(name_, item)->setUp();
    } else if (existsUnsafe(item, false) &&
               !RegistryFactory::get().external()) {
      // If the active plugin is within an extension we must wait.
      // An extension will first broadcast the registry, then receive the list
      // of active plugins, active them if they are extension-local, and finally
      // start their extension socket.
      status = pingExtension(getExtensionSocket(external_.at(item)));
    }

    if (!status.ok()) {
      break;
    }
  }
  return status;
}

RegistryRoutes RegistryInterface::getRoutes() const {
  ReadLock lock(mutex_);

  RegistryRoutes route_table;
  for (const auto& item : items_) {
    if (isInternalUnsafe(item.first)) {
      // This is an internal plugin, do not include the route.
      continue;
    }

    bool has_alias = false;
    for (const auto& alias : aliases_) {
      if (alias.second == item.first) {
        // If the item name is masked by at least one alias, it will not
        // broadcast under the internal item name.
        route_table[alias.first] = item.second->routeInfo();
        has_alias = true;
      }
    }

    if (!has_alias) {
      route_table[item.first] = item.second->routeInfo();
    }
  }
  return route_table;
}

Status RegistryInterface::call(const std::string& item_name,
                               const PluginRequest& request,
                               PluginResponse& response) {
  PluginRef plugin;
  {
    ReadLock lock(mutex_);

    // Search local plugins (items) for the plugin.
    if (items_.count(item_name) > 0) {
      plugin = items_.at(item_name);
    }
  }
  if (plugin) {
    return plugin->call(request, response);
  }

  RouteUUID uuid;
  {
    ReadLock lock(mutex_);

    // Check if the item was broadcasted as a plugin within an extension.
    if (external_.count(item_name) > 0) {
      // The item is a registered extension, call the extension by UUID.
      uuid = external_.at(item_name);
    } else if (routes_.count(item_name) > 0) {
      // The item has a route, but no extension, pass in the route info.
      response = routes_.at(item_name);
      return Status::success();
    } else if (RegistryFactory::get().external()) {
      // If this is an extension's registry forward unknown calls to the core.
      uuid = 0;
    } else {
      return Status::failure("Cannot call registry item: " + item_name);
    }
  }

  return callExtension(uuid, name_, item_name, request, response);
}

Status RegistryInterface::addAlias(const std::string& item_name,
                                   const std::string& alias) {
  WriteLock lock(mutex_);

  if (aliases_.count(alias) > 0) {
    return Status::failure("Duplicate alias: " + alias);
  }
  aliases_[alias] = item_name;
  return Status::success();
}

std::string RegistryInterface::getAlias(const std::string& alias) const {
  ReadLock lock(mutex_);

  if (aliases_.count(alias) == 0) {
    return alias;
  }
  return aliases_.at(alias);
}

Status RegistryInterface::addPlugin(const std::string& plugin_name,
                                    const PluginRef& plugin_item,
                                    bool internal) {
  WriteLock lock(mutex_);

  if (items_.count(plugin_name) > 0) {
    return Status::failure("Duplicate registry item exists: " + plugin_name);
  }

  plugin_item->setName(plugin_name);
  items_.emplace(std::make_pair(plugin_name, plugin_item));

  // The item can be listed as internal, meaning it does not broadcast.
  if (internal) {
    internal_.push_back(plugin_name);
  }

  return Status::success();
}

void RegistryInterface::setUp() {
  UpgradeLock lock(mutex_);

  // If this registry does not auto-setup do NOT setup the registry items.
  if (!auto_setup_) {
    return;
  }

  // If the registry is using a single 'active' plugin, setUp that plugin.
  // For config and logger, only setUp the selected plugin.
  if (active_.size() != 0 && existsUnsafe(active_, true)) {
    items_.at(active_)->setUp();
    return;
  }

  // Try to set up each of the registry items.
  // If they fail, remove them from the registry.
  std::vector<std::string> failed;
  for (auto& item : items_) {
    if (!item.second->setUp().ok()) {
      failed.push_back(item.first);
    }
  }

  {
    WriteUpgradeLock wlock(lock);
    for (const auto& failed_item : failed) {
      removeUnsafe(failed_item);
    }
  }
}

void RegistryInterface::configure() {
  ReadLock lock(mutex_);

  if (!active_.empty() && existsUnsafe(active_, true)) {
    items_.at(active_)->configure();
  } else {
    for (auto& item : items_) {
      item.second->configure();
    }
  }
}

Status RegistryInterface::addExternal(const RouteUUID& uuid,
                                      const RegistryRoutes& routes) {
  // Add each route name (item name) to the tracking.
  for (const auto& route : routes) {
    // Keep the routes info assigned to the registry.
    {
      WriteLock wlock(mutex_);
      routes_[route.first] = route.second;
    }

    auto status = addExternalPlugin(route.first, route.second);

    if (status.ok()) {
      WriteLock wlock(mutex_);
      external_[route.first] = uuid;
    } else {
      return status;
    }
  }

  return Status::success();
}

/// Remove all the routes for a given uuid.
void RegistryInterface::removeExternal(const RouteUUID& uuid) {
  std::vector<std::string> removed_items;

  // Create list of items to remove by filtering uuid
  {
    ReadLock lock(mutex_);
    for (const auto& item : external_) {
      if (item.second == uuid) {
        removed_items.push_back(item.first);
      }
    }

    for (const auto& item : removed_items) {
      removeExternalPlugin(item);
    }
  }

  // Remove items belonging to the external uuid.
  {
    WriteLock lock(mutex_);
    for (const auto& item : removed_items) {
      external_.erase(item);
      routes_.erase(item);
    }
  }
}

/// Facility method to check if a registry item exists.
bool RegistryInterface::exists(const std::string& item_name, bool local) const {
  ReadLock lock(mutex_);

  return existsUnsafe(item_name, local);
}

/// Facility method to list the registry item identifiers.
std::vector<std::string> RegistryInterface::names() const {
  ReadLock lock(mutex_);

  std::vector<std::string> names;
  for (const auto& item : items_) {
    names.push_back(item.first);
  }

  // Also add names of external plugins.
  for (const auto& item : external_) {
    names.push_back(item.first);
  }
  return names;
}

std::map<std::string, PluginRef> RegistryInterface::plugins() {
  ReadLock lock(mutex_);

  return items_;
}

void RegistryInterface::setname(const std::string& name) {
  WriteLock lock(mutex_);

  name_ = name;
}

bool RegistryInterface::isInternalUnsafe(const std::string& item_name) const {
  if (std::find(internal_.begin(), internal_.end(), item_name) ==
      internal_.end()) {
    return false;
  }
  return true;
}

bool RegistryInterface::existsUnsafe(const std::string& item_name,
                                     bool local) const {
  bool has_local = (items_.count(item_name) > 0);
  bool has_external = (external_.count(item_name) > 0);
  bool has_route = (routes_.count(item_name) > 0);
  return (local) ? has_local : has_local || has_external || has_route;
}

AutoRegisterInterface::AutoRegisterInterface(const char* _type,
                                             const char* _name,
                                             bool optional)
    : type_(_type), name_(_name), optional_(optional) {}

AutoRegisterSet& AutoRegisterInterface::registries() {
  static AutoRegisterSet registries_;
  return registries_;
}

AutoRegisterSet& AutoRegisterInterface::plugins() {
  static AutoRegisterSet plugins_;
  return plugins_;
}

void AutoRegisterInterface::autoloadRegistry(
    std::unique_ptr<AutoRegisterInterface> ar_) {
  registries().push_back(std::move(ar_));
}

void AutoRegisterInterface::autoloadPlugin(
    std::unique_ptr<AutoRegisterInterface> ar_) {
  plugins().push_back(std::move(ar_));
}

void registryAndPluginInit() {
  for (const auto& it : AutoRegisterInterface::registries()) {
    it->run();
  }

  for (const auto& it : AutoRegisterInterface::plugins()) {
    it->run();
  }

  AutoRegisterSet().swap(AutoRegisterInterface::registries());
  AutoRegisterSet().swap(AutoRegisterInterface::plugins());
}

} // namespace osquery

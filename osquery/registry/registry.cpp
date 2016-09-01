/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <cstdlib>
#include <sstream>

#ifndef WIN32
#include <dlfcn.h>
#endif

#include <osquery/extensions.h>
#include <osquery/json_parser.h>
#include <osquery/logger.h>
#include <osquery/registry.h>

#include "osquery/core/conversions.h"

namespace pt = boost::property_tree;

namespace osquery {

HIDDEN_FLAG(bool, registry_exceptions, false, "Allow plugin exceptions");

using InitializerMap = std::map<std::string, InitializerInterface*>;

InitializerMap& registry_initializer() {
  static InitializerMap registry_;
  return registry_;
}

InitializerMap& plugin_initializer() {
  static InitializerMap plugin_;
  return plugin_;
}

void registerRegistry(InitializerInterface* const item) {
  if (item != nullptr) {
    registry_initializer().insert({item->id(), item});
  }
}

void registerPlugin(InitializerInterface* const item) {
  if (item != nullptr) {
    plugin_initializer().insert({item->id(), item});
  }
}

void registryAndPluginInit() {
  for (const auto& it : registry_initializer()) {
    it.second->run();
  }

  for (const auto& it : plugin_initializer()) {
    it.second->run();
  }
}

void RegistryHelperCore::remove(const std::string& item_name) {
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

bool RegistryHelperCore::isInternal(const std::string& item_name) const {
  if (std::find(internal_.begin(), internal_.end(), item_name) ==
      internal_.end()) {
    return false;
  }
  return true;
}

Status RegistryHelperCore::setActive(const std::string& item_name) {
  // Default support multiple active plugins.
  for (const auto& item : osquery::split(item_name, ",")) {
    if (items_.count(item) == 0 && external_.count(item) == 0) {
      return Status(1, "Unknown registry plugin: " + item);
    }
  }

  Status status(0, "OK");
  active_ = item_name;
  // The active plugin is setup when initialized.
  for (const auto& item : osquery::split(item_name, ",")) {
    if (exists(item, true)) {
      status = Registry::get(name_, item)->setUp();
    } else if (exists(item, false) && !Registry::external()) {
      // If the active plugin is within an extension we must wait.
      // An extension will first broadcast the registry, then receive the list
      // of active plugins, active them if they are extension-local, and finally
      // start their extension socket.
      status = pingExtension(getExtensionSocket(external_.at(item_name)));
    }
  }
  return status;
}

const std::string& RegistryHelperCore::getActive() const {
  return active_;
}

RegistryRoutes RegistryHelperCore::getRoutes() const {
  RegistryRoutes route_table;
  for (const auto& item : items_) {
    if (isInternal(item.first)) {
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

Status RegistryHelperCore::call(const std::string& item_name,
                                const PluginRequest& request,
                                PluginResponse& response) {
  // Search local plugins (items) for the plugin.
  if (items_.count(item_name) > 0) {
    return items_.at(item_name)->call(request, response);
  }

  // Check if the item was broadcasted as a plugin within an extension.
  if (external_.count(item_name) > 0) {
    // The item is a registered extension, call the extension by UUID.
    return callExtension(
        external_.at(item_name), name_, item_name, request, response);
  } else if (routes_.count(item_name) > 0) {
    // The item has a route, but no extension, pass in the route info.
    response = routes_.at(item_name);
    return Status(0, "Route only");
  } else if (Registry::external()) {
    // If this is an extension's registry forward unknown calls to the core.
    return callExtension(0, name_, item_name, request, response);
  }

  return Status(1, "Cannot call registry item: " + item_name);
}

Status RegistryHelperCore::addAlias(const std::string& item_name,
                                    const std::string& alias) {
  if (aliases_.count(alias) > 0) {
    return Status(1, "Duplicate alias: " + alias);
  }
  aliases_[alias] = item_name;
  return Status(0, "OK");
}

const std::string& RegistryHelperCore::getAlias(
    const std::string& alias) const {
  if (aliases_.count(alias) == 0) {
    return alias;
  }
  return aliases_.at(alias);
}

Status RegistryHelperCore::add(const std::string& item_name, bool internal) {
  // The item can be listed as internal, meaning it does not broadcast.
  if (internal) {
    internal_.push_back(item_name);
  }

  // The item may belong to a module.
  if (RegistryFactory::usingModule()) {
    modules_[item_name] = RegistryFactory::getModule();
  }

  return Status(0, "OK");
}

void RegistryHelperCore::setUp() {
  // If this registry does not auto-setup do NOT setup the registry items.
  if (!auto_setup_) {
    return;
  }

  // If the registry is using a single 'active' plugin, setUp that plugin.
  // For config and logger, only setUp the selected plugin.
  if (active_.size() != 0 && exists(active_, true)) {
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

  for (const auto& failed_item : failed) {
    remove(failed_item);
  }
}

void RegistryHelperCore::configure() {
  if (!active_.empty() && exists(active_, true)) {
    items_.at(active_)->configure();
  } else {
    for (auto& item : items_) {
      item.second->configure();
    }
  }
}

Status RegistryHelperCore::addExternal(const RouteUUID& uuid,
                                       const RegistryRoutes& routes) {
  // Add each route name (item name) to the tracking.
  for (const auto& route : routes) {
    // Keep the routes info assigned to the registry.
    routes_[route.first] = route.second;
    auto status = addExternalPlugin(route.first, route.second);
    external_[route.first] = uuid;
    if (!status.ok()) {
      return status;
    }
  }
  return Status(0, "OK");
}

/// Remove all the routes for a given uuid.
void RegistryHelperCore::removeExternal(const RouteUUID& uuid) {
  std::vector<std::string> removed_items;
  for (const auto& item : external_) {
    if (item.second == uuid) {
      removeExternalPlugin(item.first);
      removed_items.push_back(item.first);
    }
  }

  // Remove items belonging to the external uuid.
  for (const auto& item : removed_items) {
    external_.erase(item);
    routes_.erase(item);
  }
}

/// Facility method to check if a registry item exists.
bool RegistryHelperCore::exists(const std::string& item_name,
                                bool local) const {
  bool has_local = (items_.count(item_name) > 0);
  bool has_external = (external_.count(item_name) > 0);
  bool has_route = (routes_.count(item_name) > 0);
  return (local) ? has_local : has_local || has_external || has_route;
}

/// Facility method to list the registry item identifiers.
std::vector<std::string> RegistryHelperCore::names() const {
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

/// Facility method to count the number of items in this registry.
size_t RegistryHelperCore::count() const {
  return items_.size();
}

/// Allow the registry to introspect into the registered name (for logging).
void RegistryHelperCore::setName(const std::string& name) {
  name_ = name;
}

const std::map<std::string, PluginRegistryHelperRef>& RegistryFactory::all() {
  return instance().registries_;
}

PluginRegistryHelperRef RegistryFactory::registry(
    const std::string& registry_name) {
  return instance().registries_.at(registry_name);
}

const std::map<std::string, PluginRef> RegistryFactory::all(
    const std::string& registry_name) {
  return instance().registry(registry_name)->all();
}

PluginRef RegistryFactory::get(const std::string& registry_name,
                               const std::string& item_name) {
  return instance().registry(registry_name)->get(item_name);
}

RegistryBroadcast RegistryFactory::getBroadcast() {
  RegistryBroadcast broadcast;
  for (const auto& registry : instance().registries_) {
    broadcast[registry.first] = registry.second->getRoutes();
  }
  return broadcast;
}

Status RegistryFactory::addBroadcast(const RouteUUID& uuid,
                                     const RegistryBroadcast& broadcast) {
  auto& self = instance();
  WriteLock lock(self.mutex_);
  if (self.extensions_.count(uuid) > 0) {
    return Status(1, "Duplicate extension UUID: " + std::to_string(uuid));
  }

  // Make sure the extension does not broadcast conflicting registry items.
  if (!Registry::allowDuplicates()) {
    for (const auto& registry : broadcast) {
      for (const auto& item : registry.second) {
        if (Registry::exists(registry.first, item.first)) {
          VLOG(1) << "Extension " << uuid
                  << " has duplicate plugin name: " << item.first
                  << " in registry: " << registry.first;
          return Status(1, "Duplicate registry item: " + item.first);
        }
      }
    }
  }

  // Once duplication is satisfied call each registry's addExternal.
  Status status;
  for (const auto& registry : broadcast) {
    status = RegistryFactory::registry(registry.first)
                 ->addExternal(uuid, registry.second);
    if (!status.ok()) {
      // If any registry fails to add the set of external routes, stop.
      break;
    }

    for (const auto& plugin : registry.second) {
      VLOG(1) << "Extension " << uuid << " registered " << registry.first
              << " plugin " << plugin.first;
    }
  }

  // If any registry failed, remove each (assume a broadcast is atomic).
  if (!status.ok()) {
    for (const auto& registry : broadcast) {
      Registry::registry(registry.first)->removeExternal(uuid);
    }
  }
  self.extensions_.insert(uuid);
  return status;
}

Status RegistryFactory::removeBroadcast(const RouteUUID& uuid) {
  auto& self = instance();
  WriteLock lock(self.mutex_);
  if (instance().extensions_.count(uuid) == 0) {
    return Status(1, "Unknown extension UUID: " + std::to_string(uuid));
  }

  for (const auto& registry : instance().registries_) {
    registry.second->removeExternal(uuid);
  }
  instance().extensions_.erase(uuid);
  return Status(0, "OK");
}

/// Adds an alias for an internal registry item. This registry will only
/// broadcast the alias name.
Status RegistryFactory::addAlias(const std::string& registry_name,
                                 const std::string& item_name,
                                 const std::string& alias) {
  if (instance().registries_.count(registry_name) == 0) {
    return Status(1, "Unknown registry: " + registry_name);
  }
  return instance().registries_.at(registry_name)->addAlias(item_name, alias);
}

/// Returns the item_name or the item alias if an alias exists.
const std::string& RegistryFactory::getAlias(const std::string& registry_name,
                                             const std::string& alias) {
  if (instance().registries_.count(registry_name) == 0) {
    return alias;
  }
  return instance().registries_.at(registry_name)->getAlias(alias);
}

Status RegistryFactory::call(const std::string& registry_name,
                             const std::string& item_name,
                             const PluginRequest& request,
                             PluginResponse& response) {
  // Forward factory call to the registry.
  try {
    if (item_name.find(",") != std::string::npos) {
      // Call is multiplexing plugins (usually for multiple loggers).
      for (const auto& item : osquery::split(item_name, ",")) {
        registry(registry_name)->call(item, request, response);
      }
      // All multiplexed items are called without regard for statuses.
      return Status(0);
    }
    return registry(registry_name)->call(item_name, request, response);
  } catch (const std::exception& e) {
    LOG(ERROR) << registry_name << " registry " << item_name
               << " plugin caused exception: " << e.what();
    if (FLAGS_registry_exceptions) {
      throw;
    }
    return Status(1, e.what());
  } catch (...) {
    LOG(ERROR) << registry_name << " registry " << item_name
               << " plugin caused unknown exception";
    if (FLAGS_registry_exceptions) {
      throw std::runtime_error(registry_name + ": " + item_name + " failed");
    }
    return Status(2, "Unknown exception");
  }
}

Status RegistryFactory::call(const std::string& registry_name,
                             const std::string& item_name,
                             const PluginRequest& request) {
  PluginResponse response;
  // Wrapper around a call expecting a response.
  return call(registry_name, item_name, request, response);
}

Status RegistryFactory::call(const std::string& registry_name,
                             const PluginRequest& request,
                             PluginResponse& response) {
  auto& plugin = registry(registry_name)->getActive();
  return call(registry_name, plugin, request, response);
}

Status RegistryFactory::call(const std::string& registry_name,
                             const PluginRequest& request) {
  PluginResponse response;
  return call(registry_name, request, response);
}

Status RegistryFactory::callTable(const std::string& table_name,
                                  QueryContext& context,
                                  PluginResponse& response) {
  auto& tables = registry("table")->items_;
  // This only works for local tables.
  if (tables.count(table_name) > 0) {
    auto plugin = std::dynamic_pointer_cast<TablePlugin>(tables.at(table_name));
    response = plugin->generate(context);
    return Status(0);
  } else {
    // If the table is not local then it does not benefit from complex contexts.
    PluginRequest request = {{"action", "generate"}};
    TablePlugin::setRequestFromContext(context, request);
    return call("table", table_name, request, response);
  }
}

Status RegistryFactory::setActive(const std::string& registry_name,
                                  const std::string& item_name) {
  return registry(registry_name)->setActive(item_name);
}

const std::string& RegistryFactory::getActive(
    const std::string& registry_name) {
  return registry(registry_name)->getActive();
}

void RegistryFactory::setUp() {
  for (const auto& registry : instance().all()) {
    registry.second->setUp();
  }
}

bool RegistryFactory::exists(const std::string& registry_name,
                             const std::string& item_name,
                             bool local) {
  if (instance().registries_.count(registry_name) == 0) {
    return false;
  }

  // Check the registry.
  return registry(registry_name)->exists(item_name, local);
}

std::vector<std::string> RegistryFactory::names() {
  std::vector<std::string> names;
  for (const auto& registry : all()) {
    names.push_back(registry.second->getName());
  }
  return names;
}

std::vector<std::string> RegistryFactory::names(
    const std::string& registry_name) {
  if (instance().registries_.at(registry_name) == 0) {
    std::vector<std::string> names;
    return names;
  }
  return instance().registry(registry_name)->names();
}

std::vector<RouteUUID> RegistryFactory::routeUUIDs() {
  auto& self = instance();
  WriteLock lock(self.mutex_);
  std::vector<RouteUUID> uuids;
  for (const auto& extension : self.extensions_) {
    uuids.push_back(extension);
  }
  return uuids;
}

size_t RegistryFactory::count() {
  return instance().registries_.size();
}

size_t RegistryFactory::count(const std::string& registry_name) {
  if (instance().registries_.count(registry_name) == 0) {
    return 0;
  }
  return instance().registry(registry_name)->count();
}

const std::map<RouteUUID, ModuleInfo>& RegistryFactory::getModules() {
  return instance().modules_;
}

RouteUUID RegistryFactory::getModule() {
  return instance().module_uuid_;
}

bool RegistryFactory::usingModule() {
  // Check if the registry is allowing a module's registrations.
  return (!instance().locked() && instance().module_uuid_ != 0);
}

void RegistryFactory::shutdownModule() {
  instance().locked(true);
  instance().module_uuid_ = 0;
}

void RegistryFactory::initModule(const std::string& path) {
  // Begin a module initialization, lock until the module is determined
  // appropriate by requesting a call to `declareModule`.
  instance().module_uuid_ = (RouteUUID)rand();
  instance().modules_[getModule()].path = path;
  instance().locked(true);
}

void RegistryFactory::declareModule(const std::string& name,
                                    const std::string& version,
                                    const std::string& min_sdk_version,
                                    const std::string& sdk_version) {
  // Check the min_sdk_version against the Registry's SDK version.
  auto& module = instance().modules_[instance().module_uuid_];
  module.name = name;
  module.version = version;
  module.sdk_version = sdk_version;
  instance().locked(false);
}

RegistryModuleLoader::RegistryModuleLoader(const std::string& path)
    : handle_(nullptr), path_(path) {
  // Tell the registry that we are attempting to construct a module.
  // Locking the registry prevents the module's global initialization from
  // adding or creating registry items.
  RegistryFactory::initModule(path_);

  handle_ = platformModuleOpen(path_);
  if (handle_ == nullptr) {
    VLOG(1) << "Failed to load module: " << path_;
    VLOG(1) << platformModuleGetError();
    return;
  }

  // The module should have called RegistryFactory::declareModule and unlocked
  // the registry for modification. The module should have done this using
  // the SDK's CREATE_MODULE macro, which adds the global-scope constructor.
  if (RegistryFactory::locked()) {
    VLOG(1) << "Failed to declare module: " << path_;
    platformModuleClose(handle_);
    handle_ = nullptr;
  }
}

void RegistryModuleLoader::init() {
  if (handle_ == nullptr || RegistryFactory::locked()) {
    handle_ = nullptr;
    return;
  }

  // Locate a well-known symbol in the module.
  // This symbol name is protected against rewriting when the module uses the
  // SDK's CREATE_MODULE macro.
  auto initializer =
      (ModuleInitalizer)platformModuleGetSymbol(handle_, "initModule");
  if (initializer != nullptr) {
    initializer();
    VLOG(1) << "Initialized module: " << path_;
  } else {
    VLOG(1) << "Failed to initialize module: " << path_;
    VLOG(1) << platformModuleGetError();
    platformModuleClose(handle_);
    handle_ = nullptr;
  }
}

RegistryModuleLoader::~RegistryModuleLoader() {
  if (handle_ == nullptr) {
    // The module was not loaded or did not initalize.
    RegistryFactory::instance().modules_.erase(RegistryFactory::getModule());
  }

  // We do not close the module, and thus are OK with losing a reference to the
  // module's handle. Attempting to close and clean up is very expensive for
  // very little value/features.
  if (!RegistryFactory::locked()) {
    RegistryFactory::shutdownModule();
  }
  // No need to clean this resource.
  handle_ = nullptr;
}

void Plugin::getResponse(const std::string& key,
                         const PluginResponse& response,
                         boost::property_tree::ptree& tree) {
  for (const auto& item : response) {
    boost::property_tree::ptree child;
    for (const auto& item_detail : item) {
      child.put(item_detail.first, item_detail.second);
    }
    tree.add_child(key, child);
  }
}

void Plugin::setResponse(const std::string& key,
                         const boost::property_tree::ptree& tree,
                         PluginResponse& response) {
  std::ostringstream output;
  try {
    boost::property_tree::write_json(output, tree, false);
  } catch (const pt::json_parser::json_parser_error& e) {
    UNUSED_PARAMETER(e);

    // The plugin response could not be serialized.
  }
  response.push_back({{key, output.str()}});
}
}

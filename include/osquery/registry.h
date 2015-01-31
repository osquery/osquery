/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant 
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <map>
#include <mutex>
#include <vector>

#include <boost/noncopyable.hpp>
#include <boost/property_tree/ptree.hpp>

#include <osquery/status.h>

namespace osquery {

#define CREATE_REGISTRY(type, name)                         \
  namespace registry {                                      \
  const auto type##Registry = Registry::create<type>(name); \
  }

#define CREATE_LAZY_REGISTRY(type, name)                           \
  namespace registry {                                             \
  const auto type##Registry = Registry::create<type>(name, false); \
  }

#define REGISTER(type, registry, name) \
  const auto type##RegistryItem = Registry::add<type>(registry, name);

/// A plugin (registry item) may return a custom key value map with its Route.
typedef std::map<std::string, std::string> RouteInfo;
/// Registry routes are a map of item name to each optional RouteInfo.
typedef std::map<std::string, RouteInfo> RegistryRoutes;
/// An extension or core's broadcast includes routes from every Registry.
typedef std::map<std::string, RegistryRoutes> RegistryBroadcast;

/**
 * @brief The request part of a plugin (registry item's) call.
 *
 * To use a plugin use Registry::call with a request and response.
 * The request portion is usually simple and normally includes an "action"
 * key where the value is the action you want to perform on the plugin.
 * Refer to the registry's documentation for the actions supported by
 * each of its plugins.
 */
typedef std::map<std::string, std::string> PluginRequest;
/**
 * @brief The reponse part of a plugin (registry item's) call.
 *
 * If a Registry::call succeeds it will fill in a PluginResponse.
 * This reponse is a vector of key value maps.
 */
typedef std::vector<PluginRequest> PluginResponse;

/**
 * @brief The core interface for each registry type.
 *
 * The osquery Registry is partitioned into types. These are literal types
 * but use a canonical string key for lookups and actions.
 * Registries are created using Registry::create with a RegistryType and key.
 */
template <class RegistryType>
class RegistryCore {
 protected:
  typedef std::shared_ptr<RegistryType> RegistryTypeRef;
  virtual void type() {}

 public:
  RegistryCore(bool auto_setup = true) : auto_setup_(auto_setup) {}

  /**
   * @brief Add a plugin to this registry by allocating and indexing
   * a type Item and a key identifier.
   *
   * @param item_name An identifier for this registry plugin.
   * @return A success/failure status.
   */
  template <class Item>
  Status add(const std::string& item_name) {
    if (items_.count(item_name) > 0) {
      return Status(1, "Duplicate registry item exists: " + item_name);
    }

    // Run the item's constructor, the setUp call will happen later.
    auto item = new Item();
    item->setName(item_name);
    // Cast the specific registry-type derived item as the API typ the registry
    // used when it was created using the registry factory.
    auto base_item = reinterpret_cast<RegistryType*>(item);
    std::shared_ptr<RegistryType> shared_item(base_item);
    items_[item_name] = shared_item;
    return Status(0, "OK");
  }

  /**
   * @brief A raw accessor for a registry plugin.
   *
   * If there is no plugin with an item_name identifier this will throw
   * and out_of_range exception.
   *
   * @param item_name An identifier for this registry plugin.
   * @return A std::shared_ptr of type RegistryType.
   */
  RegistryTypeRef get(const std::string& item_name) {
    return items_.at(item_name);
  }

  /**
   * @brief Remove a registry item by its identifier.
   *
   * @param item_name An identifier for this registry plugin.
   */
  void remove(const std::string& item_name) {
    if (items_.count(item_name) > 0) {
      items_[item_name]->tearDown();
      items_.erase(item_name);
    }
  }

  RegistryRoutes getRoutes() {
    RegistryRoutes route_table;
    for (const auto& item : items_) {
      route_table[item.first] = item.second->routeInfo();
    }
    return route_table;
  }

  /**
   * @brief The only method a plugin user should call.
   *
   * Registry plugins are used internally and externally. They may belong
   * to the process making the call or to an external process via a thrift
   * transport.
   *
   * All plugin input and output must be serializable. The plugin types
   * RegistryType usually exposes protected serialization methods for the
   * data structures used by plugins (registry items).
   *
   * @param item_name The plugin identifier to call.
   * @param request The plugin request, usually containing an action request.
   * @param response If successful, the requested information.
   * @return Success if the plugin was called, and response was filled.
   */
  Status call(const std::string& item_name,
              const PluginRequest& request,
              PluginResponse& response) {
    if (items_.count(item_name) > 0) {
      return items_[item_name]->call(request, response);
    }
    return Status(1, "Cannot call registry item: " + item_name);
  }

  const std::map<std::string, RegistryTypeRef>& all() { return items_; }

  void setUp() {
    // If this registry does not auto-setup do NOT setup the registry items.
    if (!auto_setup_) {
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

  /// Facility method to check if a registry item exists.
  bool exists(const std::string& item_name) {
    return (items_.count(item_name) > 0);
  }

  /// Facility method to list the registry item identifiers.
  std::vector<std::string> names() {
    std::vector<std::string> names;
    for (const auto& item : items_) {
      names.push_back(item.first);
    }
    return names;
  }

  /// Facility method to count the number of items in this registry.
  size_t count() { return items_.size(); }

  /// Allow the registry to introspect into the registered name (for logging).
  void setName(const std::string& name) { name_ = name; }

 private:
  /// The identifier for this registry, used to register items.
  std::string name_;
  /// A map of registered plugin instances to their registered identifier.
  std::map<std::string, RegistryTypeRef> items_;
  /// Does this registry run setUp on each registry item at initialization.
  bool auto_setup_;
};

template <class TypeAPI>
class RegistryFactory : private boost::noncopyable {
 protected:
  typedef RegistryCore<TypeAPI> RegistryTypeAPI;
  typedef std::shared_ptr<TypeAPI> TypeAPIRef;
  typedef std::shared_ptr<RegistryCore<TypeAPI> > RegistryTypeAPIRef;

 public:
  static RegistryFactory& instance() {
    static RegistryFactory instance;
    return instance;
  }

  /**
   * @brief Create a registry using a plugin type and identifier.
   *
   * A short hard for allocating a new registry type a RegistryCore and
   * plugin derived class Type or RegistryType. This shorthard performs
   * the allocation and initialization of the Type and keeps the instance
   * identified by registry_name.
   *
   * @code{.cpp}
   *   /// Instead of calling RegistryFactory::create use:
   *   CREATE_REGISTRY(Type, "registry_name");
   * @endcode
   *
   * @param registry_name The canonical name for this registry.
   * @param auto_setup Optionally set false if the registry handles setup
   * @return A non-sense int that must be casted const.
   */
  template <class Type>
  static int create(const std::string& registry_name, bool auto_setup = true) {
    if (instance().registries_.count(registry_name) > 0) {
      return 0;
    }

    auto registry =
        reinterpret_cast<RegistryTypeAPI*>(new RegistryCore<Type>(auto_setup));
    registry->setName(registry_name);
    std::shared_ptr<RegistryTypeAPI> shared_registry(registry);
    instance().registries_[registry_name] = shared_registry;
    return 0;
  }

  static RegistryTypeAPIRef registry(const std::string& registry_name) {
    return instance().registries_.at(registry_name);
  }

  template <class Item>
  static Status add(const std::string& registry_name,
                    const std::string& item_name) {
    auto registry = instance().registry(registry_name);
    return registry->template add<Item>(item_name);
  }

  static const std::map<std::string, RegistryTypeAPIRef>& all() {
    return instance().registries_;
  }

  static const std::map<std::string, TypeAPIRef>& all(
      const std::string& registry_name) {
    return instance().registry(registry_name)->all();
  }

  static TypeAPIRef get(const std::string& registry_name,
                        const std::string& item_name) {
    return instance().registry(registry_name)->get(item_name);
  }

  static RegistryBroadcast getBroadcast() {
    RegistryBroadcast broadcast;
    for (const auto& registry : instance().registries_) {
      broadcast[registry.first] = registry.second->getRoutes();
    }
    return broadcast;
  }

  static Status call(const std::string& registry_name,
                     const std::string item_name,
                     const PluginRequest& request,
                     PluginResponse& response) {
    if (instance().registries_.count(registry_name) > 0) {
      return instance().registries_[registry_name]->call(
          item_name, request, response);
    }
    return Status(1, "Cannot call " + registry_name + ":" + item_name);
  }

  static Status call(const std::string& registry_name,
                     const std::string& item_name,
                     const PluginRequest& request) {
    PluginResponse response;
    return call(registry_name, item_name, request, response);
  }

  static void setUp() {
    for (const auto& registry : instance().all()) {
      registry.second->setUp();
    }
  }

  static bool exists(const std::string& registry_name,
                     const std::string& item_name) {
    if (instance().registries_.count(registry_name) == 0) {
      return false;
    }
    return (instance().registry(registry_name)->exists(item_name));
  }

  static std::vector<std::string> names(const std::string& registry_name) {
    if (instance().registries_.at(registry_name) == 0) {
      std::vector<std::string> names;
      return names;
    }
    return instance().registry(registry_name)->names();
  }

  static size_t count() { return instance().registries_.size(); }

  static size_t count(const std::string& registry_name) {
    if (instance().registries_.count(registry_name) == 0) {
      return 0;
    }
    return instance().registry(registry_name)->count();
  }

 protected:
  RegistryFactory() {}

 public:
  std::map<std::string, RegistryTypeAPIRef> registries_;
};

class Plugin {
 public:
  /// The plugin may perform some initialization, not required.
  virtual Status setUp() { return Status(0, "Not used"); }
  /// The plugin may perform some tear down, release, not required.
  virtual void tearDown() {}
  /// The plugin may publish route info (other than registry type and name).
  virtual RouteInfo routeInfo() {
    RouteInfo info;
    return info;
  }
  /// The plugin will act on a serialized request, and if a response is needed
  /// (response is set to true) then response should be a reference to a
  /// string ready for a serialized response.
  virtual Status call(const PluginRequest& request, PluginResponse& response) {
    return Status(1, "Error");
  }

  // Set the output request key to a serialized property tree.
  // Used by the plugin to set a serialized PluginResponse.
  static void setResponse(const std::string& key,
                          const boost::property_tree::ptree& tree,
                          PluginResponse& response);
  // Get a PluginResponse key as a property tree.
  static void getResponse(const std::string& key,
                          const PluginResponse& response,
                          boost::property_tree::ptree& tree);

  /// Allow the plugin to introspect into the registered name (for logging).
  void setName(const std::string& name) { name_ = name; }

 protected:
  std::string name_;
};

/**
 * @brief The osquery Registry, refer to RegistryFactory for the caller API.
 *
 * The Registry class definition constructs the RegistryFactory behind the
 * scenes using a class definition template API call Plugin.
 * Each registry created by the RegistryFactory using RegistryFactory::create
 * will provide a plugin type called RegistryType that inherits from Plugin.
 * The actual plugins must add themselves to a registry type and should
 * implement the Plugin and RegistryType interfaces.
 */
class Registry : public RegistryFactory<Plugin> {};
}

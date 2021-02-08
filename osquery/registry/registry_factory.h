/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <map>
#include <set>
#include <string>

#include <boost/noncopyable.hpp>

#include <osquery/registry/registry_interface.h>

namespace osquery {

/// An extension or core's broadcast includes routes from every Registry.
using RegistryBroadcast = std::map<std::string, RegistryRoutes>;

class RegistryFactory : private boost::noncopyable {
 public:
  /// Singleton accessor.
  static RegistryFactory& get();

  /**
   * @brief Call a registry item.
   *
   * Registry 'calling' is the primary interaction osquery has with the Plugin
   * APIs, which register items. Each item is an instance of a specialized
   * Plugin, whose life/scope is maintained by the specific registry identified
   * by a unique name.
   *
   * The specialized plugin type will expose a `call` method that parses a
   * PluginRequest then perform some action and return a PluginResponse.
   * Each registry provides a `call` method that performs the registry item
   * (Plugin instance) look up, and passes and retrieves the request and
   * response.
   *
   * @param registry_name The unique registry name containing item_name,
   * @param item_name The name of the plugin used to REGISTER.
   * @param request The PluginRequest object handled by the Plugin item.
   * @param response The output.
   * @return A status from the Plugin.
   */
  static Status call(const std::string& registry_name,
                     const std::string& item_name,
                     const PluginRequest& request,
                     PluginResponse& response);

  /// A helper call that does not return a response (only status).
  static Status call(const std::string& registry_name,
                     const std::string& item_name,
                     const PluginRequest& request);

  /// A helper call that uses the active plugin (if the registry has one).
  static Status call(const std::string& registry_name,
                     const PluginRequest& request,
                     PluginResponse& response);

  /// A helper call that uses the active plugin (if the registry has one).
  static Status call(const std::string& registry_name,
                     const PluginRequest& request);

  /// Run `setUp` on every registry that is not marked 'lazy'.
  static void setUp();

 public:
  /// Direct access to a registry instance.
  RegistryInterfaceRef registry(const std::string& registry_name) const;

  void add(const std::string& name, RegistryInterfaceRef reg);

  /// Direct access to all registries.
  std::map<std::string, RegistryInterfaceRef> all() const;

  /// Direct access to all plugin instances for a given registry name.
  std::map<std::string, PluginRef> plugins(
      const std::string& registry_name) const;

  /// Direct access to a plugin instance.
  PluginRef plugin(const std::string& registry_name,
                   const std::string& item_name) const;

  /// Serialize this core or extension's registry.
  RegistryBroadcast getBroadcast();

  /// Add external registry items identified by a Route UUID.
  Status addBroadcast(const RouteUUID& uuid,
                      const RegistryBroadcast& broadcast);

  /// Given an extension UUID remove all external registry items.
  Status removeBroadcast(const RouteUUID& uuid);

  /// Adds an alias for an internal registry item. This registry will only
  /// broadcast the alias name.
  Status addAlias(const std::string& registry_name,
                  const std::string& item_name,
                  const std::string& alias);

  /// Returns the item_name or the item alias if an alias exists.
  std::string getAlias(const std::string& registry_name,
                       const std::string& alias) const;

  /// Set a registry's active plugin.
  Status setActive(const std::string& registry_name,
                   const std::string& item_name);

  /// Get a registry's active plugin.
  std::string getActive(const std::string& registry_name) const;

  bool exists(const std::string& registry_name) const {
    return (registries_.count(registry_name) > 0);
  }

  /// Check if a registry item exists, optionally search only local registries.
  bool exists(const std::string& registry_name,
              const std::string& item_name,
              bool local = false) const;

  /// Get a list of the registry names.
  std::vector<std::string> names() const;

  /// Get a list of the registry item names for a given registry.
  std::vector<std::string> names(const std::string& registry_name) const;

  /// Get a list of the registered extension UUIDs.
  std::vector<RouteUUID> routeUUIDs() const;

  /// Return the number of registries.
  size_t count() const {
    return registries_.size();
  }

  /// Return the number of registry items for a given registry name.
  size_t count(const std::string& registry_name) const;

  /// Enable/disable duplicate registry item support using aliasing.
  void allowDuplicates(bool allow) {
    allow_duplicates_ = allow;
  }

  /// Check if duplicate registry items using registry aliasing are allowed.
  bool allowDuplicates() {
    return allow_duplicates_;
  }

  /// Set the registry external (such that internal events are forwarded).
  /// Once set external, it should not be unset.
  void setExternal() {
    external_ = true;
  }

  /// Get the registry external status.
  bool external() {
    return external_;
  }

 private:
  /// Check if the registries are locked.
  bool locked() {
    return locked_;
  }

  /// Set the registry locked status.
  void locked(bool locked) {
    locked_ = locked;
  }

 protected:
  RegistryFactory() = default;
  virtual ~RegistryFactory() = default;

 private:
  /// Track duplicate registry item support, used for testing.
  bool allow_duplicates_{false};

  /// Track registry "locking", while locked a registry cannot add/create.
  bool locked_{false};

  /// The primary storage for constructed registries.
  std::map<std::string, RegistryInterfaceRef> registries_;

  /**
   * @brief The registry tracks the set of active extension routes.
   *
   * If an extension dies (the process ends or does not respond to a ping),
   * the registry will be notified via the extension watcher.
   * When an operation requests to use that extension route the extension
   * manager will lazily check the registry for changes.
   */
  std::set<RouteUUID> extensions_;

  /// Calling startExtension should declare the registry external.
  /// This will cause extension-internal events to forward to osquery core.
  bool external_{false};

  /// Protector for broadcast lookups and external registry mutations.
  mutable Mutex mutex_;

 private:
  friend class RegistryInterface;
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
using Registry = RegistryFactory;

namespace registries {

template <class R>
class AR : public AutoRegisterInterface {
 public:
  AR(const char* t, const char* n, bool optional)
      : AutoRegisterInterface(t, n, optional) {}

  void run() override {
    RegistryFactory::get().add(
        type_, std::make_shared<RegistryType<R>>(name_, optional_));
  }
};

template <class P>
class AP : public AutoRegisterInterface {
 public:
  AP(const char* t, const char* n, bool optional)
      : AutoRegisterInterface(t, n, optional) {}

  void run() override {
    auto registry = RegistryFactory::get().registry(type_);
    registry->add(name_, std::make_shared<P>(), optional_);
  }
};

template <class R>
struct RI {
  RI(const char* class_name,
     const char* registry_name,
     bool is_optional = false) {
    AutoRegisterInterface::autoloadRegistry(
        std::make_unique<AR<R>>(class_name, registry_name, is_optional));
  }
};

template <class P>
struct PI {
  PI(const char* registry_name,
     const char* plugin_name,
     bool is_optional = false) {
    AutoRegisterInterface::autoloadPlugin(
        std::make_unique<AP<P>>(registry_name, plugin_name, is_optional));
  }
};
} // namespace registries

#define CREATE_REGISTRY(class_name, registry_name)                             \
  namespace registries {                                                       \
  const RI<class_name> k##class_name(registry_name, registry_name, false);     \
  }

#define CREATE_LAZY_REGISTRY(class_name, registry_name)                        \
  namespace registries {                                                       \
  const RI<class_name> k##class_name(registry_name, registry_name, true);      \
  }

#define REGISTER(class_name, registry_name, plugin_name)                       \
  namespace registries {                                                       \
  const PI<class_name> k##class_name(registry_name, plugin_name, false);       \
  }

#define REGISTER_INTERNAL(class_name, registry_name, plugin_name)              \
  namespace registries {                                                       \
  const PI<class_name> k##class_name(registry_name, plugin_name, true);        \
  }

} // namespace osquery

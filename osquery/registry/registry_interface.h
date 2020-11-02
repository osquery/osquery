/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <functional>
#include <map>
#include <mutex>
#include <string>

#include <gtest/gtest_prod.h>

#include <boost/noncopyable.hpp>

#include <osquery/core/core.h>
#include <osquery/core/plugins/plugin.h>
#include <osquery/utils/mutex.h>

namespace osquery {

class Status;

using AddExternalCallback =
    std::function<Status(const std::string&, const PluginResponse&)>;

using RemoveExternalCallback = std::function<void(const std::string&)>;

/// Registry routes are a map of item name to each optional PluginReponse.
using RegistryRoutes = std::map<std::string, PluginResponse>;

using RouteUUID = uint64_t;

/**
 * @brief This is the registry interface.
 */
class RegistryInterface : private boost::noncopyable {
 public:
  explicit RegistryInterface(std::string name, bool auto_setup = false)
      : name_(std::move(name)), auto_setup_(auto_setup) {}
  virtual ~RegistryInterface() = default;

  /**
   * @brief This is the only way to add plugins to a registry.
   *
   * It must be implemented by the templated child, which knows the type of
   * registry and which can downcast the input plugin.
   *
   * @param plugin_name An indexable name for the plugin.
   * @param plugin_item A type-specific plugin reference.
   * @param internal true if this is internal to the osquery SDK.
   */
  virtual Status add(const std::string& plugin_name,
                     const PluginRef& plugin_item,
                     bool internal = false) = 0;

  /**
   * @brief Remove a registry item by its identifier.
   *
   * @param item_name An identifier for this registry plugin.
   */
  void remove(const std::string& item_name);

  /// Allow a registry type to react to configuration updates.
  virtual void configure();

  /// Check if a given plugin name is considered internal.
  bool isInternal(const std::string& item_name) const;

  /// Allow others to introspect into the routes from extensions.
  std::map<std::string, RouteUUID> getExternal() const;

  /// Get the 'active' plugin, return success with the active plugin name.
  std::string getActive() const;

  /// Allow others to introspect into the registered name (for reporting).
  virtual std::string getName() const;

  /// Facility method to check if a registry item exists.
  bool exists(const std::string& item_name, bool local = false) const;

  /// Facility method to count the number of items in this registry.
  size_t count() const;

  /// Facility method to list the registry item identifiers.
  std::vector<std::string> names() const;

  /**
   * @brief Allow a plugin to perform some setup functions when osquery starts.
   *
   * Doing work in a plugin constructor has unknown behavior. Plugins may
   * be constructed at anytime during osquery's life, including global variable
   * instantiation. To have a reliable state (aka, flags have been parsed,
   * and logs are ready to stream), do construction work in Plugin::setUp.
   *
   * The registry `setUp` will iterate over all of its registry items and call
   * their setup unless the registry is lazy (see CREATE_REGISTRY).
   */
  virtual void setUp();

  virtual PluginRef plugin(const std::string& plugin_name) const = 0;

  /// Construct and return a map of plugin names to their implementation.
  std::map<std::string, PluginRef> plugins();

  /**
   * @brief Create a routes table for this registry.
   *
   * This is called by the extensions API to allow an extension process to
   * broadcast each registry and the set of plugins (and their optional) route
   * information.
   *
   * The "table" registry and table plugins are the primary user of the route
   * information. Each plugin will include the SQL statement used to attach
   * an equivalent virtual table.
   */
  RegistryRoutes getRoutes() const;

 protected:
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
  virtual Status call(const std::string& item_name,
                      const PluginRequest& request,
                      PluginResponse& response);

  /**
   * @brief Add a set of item names broadcasted by an extension uuid.
   *
   * When an extension is registered the RegistryFactory will receive a
   * RegistryBroadcast containing a all of the extension's registry names and
   * the set of items with their optional route info. The factory depends on
   * each registry to manage calls/requests to these external plugins.
   *
   * @param uuid The uuid chosen for the extension.
   * @param routes The plugin name and optional route info list.
   * @return Success if all routes were added, failure if any failed.
   */
  Status addExternal(const RouteUUID& uuid, const RegistryRoutes& routes);

  /**
   * @brief Each RegistryType will include a trampoline into the PluginType.
   *
   * A PluginType may act on registry modifications. Each specialized registry
   * will include a trampoline method to call the plugin type's addExternal.
   *
   * @param name Plugin name (not the extension UUID).
   * @param info The route information broadcasted.
   */
  virtual Status addExternalPlugin(const std::string& name,
                                   const PluginResponse& info) const = 0;

  /// Remove all the routes for a given uuid.
  void removeExternal(const RouteUUID& uuid);

  /**
   * @brief Each RegistryType will include a trampoline into the PluginType.
   *
   * A PluginType may act on registry modifications. Each specialized registry
   * will include a trampoline method to call the plugin type's removeExternal.
   * @param name Plugin name (not the extension UUID).
   */
  virtual void removeExternalPlugin(const std::string& name) const = 0;

  /// Allow the registry to introspect into the registered name (for logging).
  void setname(const std::string& name);

  /**
   * @brief The implementation adder will call addPlugin.
   *
   * Once a downcast is completed the work for adding internal/external
   * indexes is provided here.
   */
  Status addPlugin(const std::string& plugin_name,
                   const PluginRef& plugin_item,
                   bool internal);

  /// Set an 'active' plugin to receive registry calls when no item name given.
  Status setActive(const std::string& item_name);

  /// Create a registry item alias for a given item name.
  Status addAlias(const std::string& item_name, const std::string& alias);

  /// Get the registry item name for a given alias.
  std::string getAlias(const std::string& alias) const;

 protected:
  /// The identifier for this registry, used to register items.
  std::string name_;

  /// Does this registry run setUp on each registry item at initialization.
  bool auto_setup_;

 protected:
  /// A map of registered plugin instances to their registered identifier.
  std::map<std::string, PluginRef> items_;

  /// If aliases are used, a map of alias to item name.
  std::map<std::string, std::string> aliases_;

  /// Keep a lookup of the external item name to assigned extension UUID.
  std::map<std::string, RouteUUID> external_;

  /// Keep a lookup of optional route info. The plugin may handle calls
  /// to external items differently.
  std::map<std::string, PluginResponse> routes_;

  /// Keep a lookup of registry items that are withheld from broadcast.
  std::vector<std::string> internal_;

  /// Support an 'active' mode where calls without a specific item name will
  /// be directed to the 'active' plugin.
  std::string active_;

  /// Protect concurrent accesses to object's data
  mutable Mutex mutex_;

 private:
  friend class RegistryFactory;

  void removeUnsafe(const std::string& item_name);

  bool isInternalUnsafe(const std::string& item_name) const;

  bool existsUnsafe(const std::string& item_name, bool local) const;
};

/**
 * @brief The core interface for each registry type.
 *
 * The osquery Registry is partitioned into types. These are literal types
 * but use a canonical string key for lookups and actions.
 * Registries are created using Registry::create with a RegistryType and key.
 */
template <class PluginType>
class RegistryType : public RegistryInterface {
 protected:
  using PluginTypeRef = std::shared_ptr<PluginType>;

 public:
  explicit RegistryType(const std::string& name, bool auto_setup = false)
      : RegistryInterface(name, auto_setup),
        add_(&PluginType::addExternal),
        remove_(&PluginType::removeExternal) {}
  ~RegistryType() override = default;

  Status add(const std::string& plugin_name,
             const PluginRef& plugin_item,
             bool internal = false) override {
    if (nullptr == std::dynamic_pointer_cast<PluginType>(plugin_item)) {
      throw std::runtime_error("Cannot add foreign plugin type: " +
                               plugin_name);
    }
    return addPlugin(plugin_name, plugin_item, internal);
  }

  /**
   * @brief A raw accessor for a registry plugin.
   *
   * If there is no plugin with an item_name identifier this will throw
   * and out_of_range exception.
   *
   * @param plugin_name An identifier for this registry plugin.
   * @return A std::shared_ptr of type RegistryType.
   */
  PluginRef plugin(const std::string& plugin_name) const override {
    ReadLock lock(mutex_);

    if (items_.count(plugin_name) == 0) {
      return nullptr;
    }
    return items_.at(plugin_name);
  }

  /// Trampoline function for calling the PluginType's addExternal.
  Status addExternalPlugin(const std::string& name,
                           const PluginResponse& info) const override {
    return add_(name, info);
  }

  /// Trampoline function for calling the PluginType's removeExternal.
  void removeExternalPlugin(const std::string& name) const override {
    remove_(name);
  }

 private:
  AddExternalCallback add_;
  RemoveExternalCallback remove_;

 private:
  FRIEND_TEST(EventsTests, test_event_subscriber_configure);
  FRIEND_TEST(VirtualTableTests, test_indexing_costs);
};

/// Helper definitions for a shared pointer to the basic Registry type.
using RegistryInterfaceRef = std::shared_ptr<RegistryInterface>;

class AutoRegisterInterface;
using AutoRegisterSet = std::vector<std::unique_ptr<AutoRegisterInterface>>;

class AutoRegisterInterface {
 public:
  /// The registry name, or type identifier.
  std::string type_;

  /// The registry or plugin name.
  std::string name_;

  /// Either autoload a registry, or create an internal plugin.
  bool optional_;

  AutoRegisterInterface(const char* _type, const char* _name, bool optional);
  virtual ~AutoRegisterInterface() = default;

  /// A call-in for the iterator.
  virtual void run() = 0;

 public:
  /// Access all registries.
  static AutoRegisterSet& registries();

  /// Insert a new registry.
  static void autoloadRegistry(std::unique_ptr<AutoRegisterInterface> ar_);

  /// Access all plugins.
  static AutoRegisterSet& plugins();

  /// Insert a new plugin.
  static void autoloadPlugin(std::unique_ptr<AutoRegisterInterface> ar_);
};

void registryAndPluginInit();
} // namespace osquery

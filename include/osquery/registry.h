/*
 *  Copyright (c) 2014-present, Facebook, Inc.
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
#include <set>
#include <utility>
#include <vector>

#include <boost/noncopyable.hpp>
#include <boost/property_tree/ptree.hpp>

#include <osquery/core.h>
#include <osquery/system.h>

namespace osquery {

/**
 * @brief The request part of a plugin (registry item's) call.
 *
 * To use a plugin use Registry::call with a request and response.
 * The request portion is usually simple and normally includes an "action"
 * key where the value is the action you want to perform on the plugin.
 * Refer to the registry's documentation for the actions supported by
 * each of its plugins.
 */
using PluginRequest = std::map<std::string, std::string>;

/**
 * @brief The response part of a plugin (registry item's) call.
 *
 * If a Registry::call succeeds it will fill in a PluginResponse.
 * This response is a vector of key value maps.
 */
using PluginResponse = std::vector<PluginRequest>;

/// Registry routes are a map of item name to each optional PluginReponse.
using RegistryRoutes = std::map<std::string, PluginResponse>;

/// An extension or core's broadcast includes routes from every Registry.
using RegistryBroadcast = std::map<std::string, RegistryRoutes>;

using RouteUUID = uint64_t;

using AddExternalCallback =
    std::function<Status(const std::string&, const PluginResponse&)>;

using RemoveExternalCallback = std::function<void(const std::string&)>;

/// The registry includes a single optimization for table generation.
struct QueryContext;

class Plugin : private boost::noncopyable {
 public:
  virtual ~Plugin() = default;

 public:
  /// The plugin may perform some initialization, not required.
  virtual Status setUp() {
    return Status(0, "Not used");
  }

  /// The plugin may perform some tear down, release, not required.
  virtual void tearDown() {}

  /// The plugin may react to configuration updates.
  virtual void configure() {}

  /// The plugin may publish route info (other than registry type and name).
  virtual PluginResponse routeInfo() const {
    return PluginResponse();
  }

  /**
   * @brief Plugins act by being called, using a request, returning a response.
   *
   * The plugin request is a thrift-serializable object. A response is optional
   * but the API for using a plugin's call is defined by the registry. In most
   * cases there are multiple supported call 'actions'. A registry type, or
   * the plugin class, will define the action key and supported actions.
   *
   * @param request A plugin request input, including optional action.
   * @param response A plugin response output.
   *
   * @return Status of the call, if the action was handled corrected.
   */
  virtual Status call(const PluginRequest& request,
                      PluginResponse& response) = 0;

  /// Allow the plugin to introspect into the registered name (for logging).
  virtual void setName(const std::string& name) final;

  /// Force call-sites to use #getName to access the plugin item's name.
  virtual const std::string& getName() const {
    return name_;
  }

 public:
  /// Set the output request key to a serialized property tree.
  /// Used by the plugin to set a serialized PluginResponse.
  static void setResponse(const std::string& key,
                          const boost::property_tree::ptree& tree,
                          PluginResponse& response);

  /// Get a PluginResponse key as a property tree.
  static void getResponse(const std::string& key,
                          const PluginResponse& response,
                          boost::property_tree::ptree& tree);

  /**
   * @brief Bind this plugin to an external plugin reference.
   *
   * Allow a specialized plugin type to act when an external plugin is
   * registered (e.g., a TablePlugin will attach the table name).
   *
   * @param name The broadcasted name of the plugin.
   * @param info The routing info for the owning extension.
   */
  static Status addExternal(const std::string& /*name*/,
                            const PluginResponse& /*info*/) {
    return Status(0, "Not used");
  }

  /// Allow a specialized plugin type to act when an external plugin is removed.
  static void removeExternal(const std::string& /*name*/) {}

 protected:
  /// Customized name for the plugin, usually set by the registry.
  std::string name_;
};

/// Helper definition for a shared pointer to a Plugin.
using PluginRef = std::shared_ptr<Plugin>;

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
  const std::map<std::string, RouteUUID>& getExternal() const {
    return external_;
  }

  /// Get the 'active' plugin, return success with the active plugin name.
  const std::string& getActive() const {
    return active_;
  }

  /// Allow others to introspect into the registered name (for reporting).
  virtual const std::string& getName() const {
    return name_;
  }

  /// Facility method to check if a registry item exists.
  bool exists(const std::string& item_name, bool local = false) const;

  /// Facility method to count the number of items in this registry.
  size_t count() const {
    return items_.size();
  }

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
  const std::map<std::string, PluginRef>& plugins() {
    return items_;
  }

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
  void setName(const std::string& name) {
    name_ = name;
  }

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

  /// Keep a lookup of registry items that are blacklisted from broadcast.
  std::vector<std::string> internal_;

  /// Support an 'active' mode where calls without a specific item name will
  /// be directed to the 'active' plugin.
  std::string active_;

 private:
  friend class RegistryFactory;
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

class RegistryFactory : private boost::noncopyable {
 public:
  static RegistryFactory& get() {
    static RegistryFactory instance;
    return instance;
  };

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
  std::string getActive(const std::string& registry_nane) const;

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

  AutoRegisterInterface(const char* _type, const char* _name, bool optional)
      : type_(_type), name_(_name), optional_(optional) {}
  virtual ~AutoRegisterInterface() = default;

  /// A call-in for the iterator.
  virtual void run() = 0;

 public:
  /// Access all registries.
  static AutoRegisterSet& registries() {
    static AutoRegisterSet registries_;
    return registries_;
  }

  /// Insert a new registry.
  static void autoloadRegistry(std::unique_ptr<AutoRegisterInterface> ar_) {
    registries().push_back(std::move(ar_));
  }

  /// Access all plugins.
  static AutoRegisterSet& plugins() {
    static AutoRegisterSet plugins_;
    return plugins_;
  }

  /// Insert a new plugin.
  static void autoloadPlugin(std::unique_ptr<AutoRegisterInterface> ar_) {
    plugins().push_back(std::move(ar_));
  }
};

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
  RI(const char* t, const char* n, bool o = false) {
    AutoRegisterInterface::autoloadRegistry(std::make_unique<AR<R>>(t, n, o));
  }
};

template <class P>
struct PI {
  PI(const char* t, const char* n, bool o = false) {
    AutoRegisterInterface::autoloadPlugin(std::make_unique<AP<P>>(t, n, o));
  }
};
} // namespace registries

#define CREATE_REGISTRY(t, n)                                                  \
  namespace registries {                                                       \
  const RI<t> k##t(n, n, false);                                               \
  }

#define CREATE_LAZY_REGISTRY(t, n)                                             \
  namespace registries {                                                       \
  const RI<t> k##t(n, n, true);                                                \
  }

#define REGISTER(t, r, n)                                                      \
  namespace registries {                                                       \
  const PI<t> k##t(r, n, false);                                               \
  }

#define REGISTER_INTERNAL(t, r, n)                                             \
  namespace registries {                                                       \
  const PI<t> k##t(r, n, true);                                                \
  }

void registryAndPluginInit();
} // namespace osquery

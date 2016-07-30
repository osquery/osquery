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
#include <vector>

#include <boost/noncopyable.hpp>
#include <boost/property_tree/ptree.hpp>

#include <osquery/core.h>

#include "osquery/core/process.h"

namespace osquery {

/// An opaque interface used within plugin macros.
struct InitializerInterface {
  virtual const char *id() const = 0;
  virtual void run() const = 0;
  virtual ~InitializerInterface() {}
};

/// Request a registry type for initialization.
void registerRegistry(InitializerInterface *const item);

/// Request a plugin type for initialization.
void registerPlugin(InitializerInterface *const item);

/// Allocate and instantiate one of each requested registry and plugin.
void registryAndPluginInit();

/**
 * @brief A boilerplate code helper to create a registry given a name and
 * plugin base class type.
 *
 * Registries are types of plugins, e.g., config, logger, table. They are
 * defined with a string name and Plugin derived class. There is an expectation
 * that any 'item' registered will inherit from the registry plugin-derived
 * type. But there is NO type enforcement on that intermediate class.
 *
 * This boilerplate macro puts the registry into a 'registry' namespace for
 * organization and create a global const int that may be instantiated
 * in a header or implementation code without symbol duplication.
 * The initialization is also boilerplate, whereas the Registry::create method
 * (a whole-process-lived single instance object) creates and manages the
 * registry instance.
 *
 * @param type A typename that derives from Plugin.
 * @param name A string identifier for the registry.
 */
#define CREATE_REGISTRY(type, name)                                            \
  namespace registry {                                                         \
  struct type##Registry : public InitializerInterface {                        \
    type##Registry(void) { registerRegistry(this); }                           \
    const char *id() const override { return name; }                           \
    void run() const override { Registry::create<type>(name); }                \
  };                                                                           \
  static type##Registry type##instance_;                                       \
  }

/**
 * @brief A boilerplate code helper to create a registry given a name and
 * plugin base class type. This 'lazy' registry does not run
 * Plugin::setUp on its items, so the registry will do it.
 *
 * @param type A typename that derives from Plugin.
 * @param name A string identifier for the registry.
 */
#define CREATE_LAZY_REGISTRY(type, name)                                       \
  namespace registry {                                                         \
  struct type##Registry : public InitializerInterface {                        \
    type##Registry(void) { registerRegistry(this); }                           \
    const char *id() const override { return name; }                           \
    void run() const override { Registry::create<type>(name, true); }          \
  };                                                                           \
  static type##Registry type##instance_;                                       \
  }

/**
 * @brief A boilerplate code helper to register a plugin.
 *
 * Like CREATE_REGISTRY, REGISTER creates a boilerplate global instance to
 * create an instance of the plugin type within the whole-process-lived registry
 * single instance. Registry items must derive from the `RegistryType` defined
 * by the CREATE_REGISTRY and Registry::create call.
 *
 * @param type A typename that derives from the RegistryType.
 * @param registry The string name for the registry.
 * @param name A string identifier for this registry item.
 */
#define REGISTER(type, registry, name)                                         \
  struct type##RegistryItem : public InitializerInterface {                    \
    type##RegistryItem(void) { registerPlugin(this); }                         \
    const char *id() const override { return registry "." name ; }           \
    void run() const override { Registry::add<type>(registry, name); }         \
  };                                                                           \
  static type##RegistryItem type##instance_;

/// The same as REGISTER but prevents the plugin item from being broadcasted.
#define REGISTER_INTERNAL(type, registry, name)                                \
  struct type##RegistryItem : public InitializerInterface {                    \
    type##RegistryItem(void) { registerPlugin(this); }                         \
    const char *id() const override { return registry "." name ; }           \
    void run() const override { Registry::add<type>(registry, name, true); }   \
  };                                                                           \
  static type##RegistryItem type##instance_;

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

using RouteUUID = uint16_t;
using AddExternalCallback =
    std::function<Status(const std::string&, const PluginResponse&)>;
using RemoveExternalCallback = std::function<void(const std::string&)>;

/// When a module is being initialized its information is kept in a transient
/// RegistryFactory lookup location.
struct ModuleInfo {
  std::string path;
  std::string name;
  std::string version;
  std::string sdk_version;
};

/// The call-in prototype for Registry modules.
using ModuleInitalizer = void (*)(void);

/// The registry includes a single optimization for table generation.
struct QueryContext;

template <class PluginItem>
class PluginFactory {};

class Plugin : private boost::noncopyable {
 public:
  Plugin() : name_("unnamed"){};
  virtual ~Plugin(){};

 public:
  /// The plugin may perform some initialization, not required.
  virtual Status setUp() { return Status(0, "Not used"); }

  /// The plugin may perform some tear down, release, not required.
  virtual void tearDown() {}

  /// The plugin may react to configuration updates.
  virtual void configure() {}

  /// The plugin may publish route info (other than registry type and name).
  virtual PluginResponse routeInfo() const { return PluginResponse(); }

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
  virtual Status call(const PluginRequest& request, PluginResponse& response) {
    return Status(0, "Not used");
  }

  /// Allow the plugin to introspect into the registered name (for logging).
  void setName(const std::string& name) { name_ = name; }

  /// Force callsites to use #getName to access the plugin item's name.
  virtual const std::string& getName() const { return name_; }

 public:
  // Set the output request key to a serialized property tree.
  // Used by the plugin to set a serialized PluginResponse.
  static void setResponse(const std::string& key,
                          const boost::property_tree::ptree& tree,
                          PluginResponse& response);

  // Get a PluginResponse key as a property tree.
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
  static Status addExternal(const std::string& name,
                            const PluginResponse& info) {
    return Status(0, "Not used");
  }

  /// Allow a specialized plugin type to act when an external plugin is removed.
  static void removeExternal(const std::string& name) {}

 public:
  Plugin(Plugin const&) = delete;
  Plugin& operator=(Plugin const&) = delete;

 protected:
  std::string name_;
};

class RegistryHelperCore : private boost::noncopyable {
 public:
  explicit RegistryHelperCore(bool auto_setup = false)
      : auto_setup_(auto_setup){};
  virtual ~RegistryHelperCore(){};

  /**
   * @brief Remove a registry item by its identifier.
   *
   * @param item_name An identifier for this registry plugin.
   */
  void remove(const std::string& item_name);

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

  /// Insert a named plugin into this registry.
  Status add(const std::string& item_name, bool internal = false);

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

  /// Allow a registry type to react to configuration updates.
  virtual void configure();

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

  /// Facility method to check if a registry item exists.
  bool exists(const std::string& item_name, bool local = false) const;

  /// Create a registry item alias for a given item name.
  Status addAlias(const std::string& item_name, const std::string& alias);

  /// Get the registry item name for a given alias.
  const std::string& getAlias(const std::string& alias) const;

  /// Facility method to list the registry item identifiers.
  std::vector<std::string> names() const;

  /// Facility method to count the number of items in this registry.
  size_t count() const;

  /// Allow the registry to introspect into the registered name (for logging).
  void setName(const std::string& name);

  /// Allow others to introspect into the registered name (for reporting).
  virtual const std::string& getName() const { return name_; }

  /// Check if a given plugin name is considered internal.
  bool isInternal(const std::string& item_name) const;

  /// Allow others to introspect into the routes from extensions.
  const std::map<std::string, RouteUUID>& getExternal() const {
    return external_;
  }

  /// Set an 'active' plugin to receive registry calls when no item name given.
  Status setActive(const std::string& item_name);

  /// Get the 'active' plugin, return success with the active plugin name.
  const std::string& getActive() const;

 protected:
  /// The identifier for this registry, used to register items.
  std::string name_;

  /// Does this registry run setUp on each registry item at initialization.
  bool auto_setup_;

 protected:
  /// A map of registered plugin instances to their registered identifier.
  std::map<std::string, std::shared_ptr<Plugin>> items_;

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

  /// If a module was initialized/declared then store lookup information.
  std::map<std::string, RouteUUID> modules_;

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
template <class RegistryType>
class RegistryHelper : public RegistryHelperCore {
 protected:
  using RegistryTypeRef = std::shared_ptr<RegistryType>;

 public:
  explicit RegistryHelper(bool auto_setup = false)
      : RegistryHelperCore(auto_setup),
        add_(&RegistryType::addExternal),
        remove_(&RegistryType::removeExternal){};
  virtual ~RegistryHelper() {}

  /**
   * @brief Add a plugin to this registry by allocating and indexing
   * a type Item and a key identifier.
   *
   * @code{.cpp}
   *   /// Instead of calling RegistryFactory::add use:
   *   REGISTER(Type, "registry_name", "item_name");
   * @endcode
   *
   * @param item_name An identifier for this registry plugin.
   * @param internal If true, the plugin does not broadcast.
   * @return A success/failure status.
   */
  template <class Item>
  Status add(const std::string& item_name, bool internal = false) {
    if (items_.count(item_name) > 0) {
      return Status(1, "Duplicate registry item exists: " + item_name);
    }

    // Cast the specific registry-type derived item as the API type of the
    // registry used when created using the registry factory.
    std::shared_ptr<RegistryType> item((RegistryType*)new Item());
    item->setName(item_name);
    items_[item_name] = item;
    return RegistryHelperCore::add(item_name, internal);
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
  RegistryTypeRef get(const std::string& item_name) const {
    return std::dynamic_pointer_cast<RegistryType>(items_.at(item_name));
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

  /// Construct and return a map of plugin names to their implementation.
  const std::map<std::string, RegistryTypeRef> all() const {
    std::map<std::string, RegistryTypeRef> ditems;
    for (const auto& item : items_) {
      ditems[item.first] = std::dynamic_pointer_cast<RegistryType>(item.second);
    }

    return ditems;
  }

 protected:
  /**
   * @brief Add an existing plugin to this registry, used for testing only.
   *
   * @param item A PluginType-cased registry item.
   * @return A success/failure status.
   */
  Status add(const std::shared_ptr<RegistryType>& item) {
    items_[item->getName()] = item;
    return RegistryHelperCore::add(item->getName(), true);
  }

 public:
  RegistryHelper(RegistryHelper const&) = delete;
  void operator=(RegistryHelper const&) = delete;

 private:
  AddExternalCallback add_;
  RemoveExternalCallback remove_;

 private:
  FRIEND_TEST(EventsTests, test_event_subscriber_configure);
};

/// Helper definition for a shared pointer to a Plugin.
using PluginRef = std::shared_ptr<Plugin>;

/// Helper definition for a basic-templated Registry type using a base Plugin.
using PluginRegistryHelper = RegistryHelper<Plugin>;

/// Helper definitions for a shared pointer to the basic Registry type.
using PluginRegistryHelperRef = std::shared_ptr<PluginRegistryHelper>;

/**
 * @brief A workflow manager for opening a module path and appending to the
 * core registry.
 *
 * osquery Registry modules are part of the extensions API, in that they use
 * the osquery SDK to expose additional features to the osquery core. Modules
 * do not require the Thrift interface and may be compiled as shared objects
 * and loaded late at run time once the core and internal registry has been
 * initialized and setUp.
 *
 * A ModuleLoader interprets search paths, dynamically loads the modules,
 * maintains identification within the RegistryFactory and any registries
 * the module adds items into.
 */
class RegistryModuleLoader : private boost::noncopyable {
 public:
  /// Unlock the registry, open, construct, and allow the module to declare.
  explicit RegistryModuleLoader(const std::string& path);

  /// Clear module information, 'lock' the registry.
  ~RegistryModuleLoader();

  /// Keep the symbol resolution/calling out of construction.
  void init();

 private:
  // Keep the handle for symbol resolution/calling.
  std::unique_ptr<SharedLibModule> handle_{ nullptr };

  // Keep the path for debugging/logging.
  std::string path_;

 private:
  FRIEND_TEST(RegistryTests, test_registry_modules);
};

class RegistryFactory : private boost::noncopyable {
 public:
  static RegistryFactory& instance() {
    static RegistryFactory instance;
    return instance;
  };

  /**
   * @brief Create a registry using a plugin type and identifier.
   *
   * A short hard for allocating a new registry type a RegistryHelper and
   * plugin derived class Type or RegistryType. This shorthand performs
   * the allocation and initialization of the Type and keeps the instance
   * identified by registry_name.
   *
   * @code{.cpp}
   *   /// Instead of calling RegistryFactory::create use:
   *   CREATE_REGISTRY(Type, "registry_name");
   * @endcode
   *
   * @param registry_name The canonical name for this registry.
   * @param auto_setup Set true if the registry does not setup itself
   * @return A non-sense int that must be casted const.
   */
  template <class Type>
  static int create(const std::string& registry_name, bool auto_setup = false) {
    if (locked() || instance().registries_.count(registry_name) > 0) {
      return 0;
    }

    PluginRegistryHelperRef registry(
        (PluginRegistryHelper*)new RegistryHelper<Type>(auto_setup));
    registry->setName(registry_name);
    instance().registries_[registry_name] = registry;
    return 0;
  }

  /// Direct access to a registry instance.
  static PluginRegistryHelperRef registry(const std::string& registry_name);

  /**
   * @brief Add (implies create) a Plugin to a registry.
   *
   * REGISTER and REGISTER_INTERNAL are helper macros for `add` usage.
   *
   * @code{.cpp}
   *  /// Instead of calling RegistryFactor::add use:
   *  REGISTER(Type, "registry_name", "plugin_name");
   * @endcode
   *
   * @param registry_name The canonical name for this registry.
   * @param item_name The canonical name for this plugin. Specific registries
   * may apply specialized use of the plugin name, such as table.
   * @param internal True if this plugin should not be broadcasted externally.
   */
  template <class Item>
  static Status add(const std::string& registry_name,
                    const std::string& item_name,
                    bool internal = false) {
    if (!locked()) {
      auto registry = instance().registry(registry_name);
      return registry->template add<Item>(item_name, internal);
    }
    return Status(0, "Registry locked");
  }

  /// Direct access to all registries.
  static const std::map<std::string, PluginRegistryHelperRef>& all();

  /// Direct access to all plugin instances for a given registry name.
  static const std::map<std::string, PluginRef> all(
      const std::string& registry_name);

  /// Direct access to a plugin instance.
  static PluginRef get(const std::string& registry_name,
                       const std::string& item_name);

  /// Serialize this core or extension's registry.
  static RegistryBroadcast getBroadcast();

  /// Add external registry items identified by a Route UUID.
  static Status addBroadcast(const RouteUUID& uuid,
                             const RegistryBroadcast& broadcast);

  /// Given an extension UUID remove all external registry items.
  static Status removeBroadcast(const RouteUUID& uuid);

  /// Adds an alias for an internal registry item. This registry will only
  /// broadcast the alias name.
  static Status addAlias(const std::string& registry_name,
                         const std::string& item_name,
                         const std::string& alias);

  /// Returns the item_name or the item alias if an alias exists.
  static const std::string& getAlias(const std::string& registry_name,
                                     const std::string& alias);

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

  /// A helper call optimized for table data generation.
  static Status callTable(const std::string& table_name,
                          QueryContext& context,
                          PluginResponse& response);

  /// Set a registry's active plugin.
  static Status setActive(const std::string& registry_name,
                          const std::string& item_name);

  /// Get a registry's active plugin.
  static const std::string& getActive(const std::string& registry_nane);

  /// Run `setUp` on every registry that is not marked 'lazy'.
  static void setUp();

  /// Check if a registry item exists, optionally search only local registries.
  static bool exists(const std::string& registry_name,
                     const std::string& item_name,
                     bool local = false);

  /// Get a list of the registry names.
  static std::vector<std::string> names();

  /// Get a list of the registry item names for a given registry.
  static std::vector<std::string> names(const std::string& registry_name);

  /// Get a list of the registered extension UUIDs.
  static std::vector<RouteUUID> routeUUIDs();

  /// Return the number of registries.
  static size_t count();

  /// Return the number of registry items for a given registry name.
  static size_t count(const std::string& registry_name);

  /// Enable/disable duplicate registry item support using aliasing.
  static void allowDuplicates(bool allow) {
    instance().allow_duplicates_ = allow;
  }

  /// Check if duplicate registry items using registry aliasing are allowed.
  static bool allowDuplicates() { return instance().allow_duplicates_; }

  /// Declare a module for initialization and subsequent registration attempts
  static void declareModule(const std::string& name,
                            const std::string& version,
                            const std::string& min_sdk_version,
                            const std::string& sdk_version);

  /// Access module metadata.
  static const std::map<RouteUUID, ModuleInfo>& getModules();

  /// Set the registry external (such that internal events are forwarded).
  /// Once set external, it should not be unset.
  static void setExternal() { instance().external_ = true; }

  /// Get the registry external status.
  static bool external() { return instance().external_; }

 private:
  /// Access the current initializing module UUID.
  static RouteUUID getModule();

  /// Check if the registry is allowing module registrations.
  static bool usingModule();

  /// Initialize a module for lookup, resolution, and its registrations.
  static void initModule(const std::string& path);

  static void shutdownModule();

  /// Check if the registries are locked.
  static bool locked() { return instance().locked_; }

  /// Set the registry locked status.
  static void locked(bool locked) { instance().locked_ = locked; }

 public:
  RegistryFactory(RegistryFactory const&) = delete;
  RegistryFactory& operator=(RegistryFactory const&) = delete;

 protected:
  RegistryFactory()
      : allow_duplicates_(false),
        locked_(false),
        module_uuid_(0),
        external_(false) {}
  virtual ~RegistryFactory() {}

 private:
  /// Track duplicate registry item support, used for testing.
  bool allow_duplicates_{false};

  /// Track registry "locking", while locked a registry cannot add/create.
  bool locked_{false};

  /// The primary storage for constructed registries.
  std::map<std::string, PluginRegistryHelperRef> registries_;

  /**
   * @brief The registry tracks the set of active extension routes.
   *
   * If an extension dies (the process ends or does not respond to a ping),
   * the registry will be notified via the extension watcher.
   * When an operation requests to use that extension route the extension
   * manager will lazily check the registry for changes.
   */
  std::set<RouteUUID> extensions_;

  /**
   * @brief The registry tracks loaded extension module metadata/info.
   *
   * Each extension module is assigned a transient RouteUUID for identification
   * those route IDs are passed to each registry to identify which plugin
   * items belong to modules, similarly to extensions.
   */
  std::map<RouteUUID, ModuleInfo> modules_;

  /// During module initialization store the current-working module ID.
  RouteUUID module_uuid_{0};

  /// Calling startExtension should declare the registry external.
  /// This will cause extension-internal events to forward to osquery core.
  bool external_{false};

  /// Protector for broadcast lookups and external registry mutations.
  mutable Mutex mutex_;

 private:
  friend class RegistryHelperCore;
  friend class RegistryModuleLoader;
  FRIEND_TEST(RegistryTests, test_registry_modules);
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
}

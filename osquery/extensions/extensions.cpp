/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <map>
#include <set>
#include <string>
#include <tuple>
#include <vector>

#include <boost/algorithm/string/trim.hpp>
#include <boost/optional.hpp>

#include <osquery/core/core.h>
#include <osquery/core/flagalias.h>
#include <osquery/core/shutdown.h>
#include <osquery/core/system.h>
#include <osquery/extensions/interface.h>
#include <osquery/filesystem/fileops.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/process/process.h>
#include <osquery/registry/registry.h>
#include <osquery/sql/sql.h>

#include <osquery/utils/config/default_paths.h>
#include <osquery/utils/conversions/join.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/utils/info/platform_type.h>
#include <osquery/utils/info/version.h>

namespace fs = boost::filesystem;

namespace osquery {

enum class ExtendableType {
  EXTENSION = 1,
};

using ExtendableTypeSet = std::map<ExtendableType, std::set<std::string>>;

namespace {

/// Map of acceptable file extensions for extension binaries.
const std::map<PlatformType, ExtendableTypeSet> kFileExtensions{
    {PlatformType::TYPE_WINDOWS,
     {{ExtendableType::EXTENSION, {".exe", ".ext"}}}},
    {PlatformType::TYPE_LINUX, {{ExtendableType::EXTENSION, {".ext"}}}},
    {PlatformType::TYPE_OSX, {{ExtendableType::EXTENSION, {".ext"}}}},
};

/// Millisecond latency between initializing manager pings.
const size_t kExtensionInitializeLatency{20};

} // namespace

CLI_FLAG(bool, disable_extensions, false, "Disable extension API");

CLI_FLAG(string,
         extensions_socket,
         OSQUERY_SOCKET "osquery.em",
         "Path to the extensions UNIX domain socket");

CLI_FLAG(string,
         extensions_autoload,
         OSQUERY_HOME "extensions.load",
         "Optional path to a list of autoloaded & managed extensions");

CLI_FLAG(string,
         extensions_timeout,
         "3",
         "Seconds to wait for autoloaded extensions");

CLI_FLAG(string,
         extensions_interval,
         "3",
         "Seconds delay between connectivity checks");

SHELL_FLAG(string, extension, "", "Path to a single extension to autoload");

CLI_FLAG(string,
         extensions_require,
         "",
         "Comma-separated list of required extensions");

/**
 * @brief Alias the extensions_socket (used by core) to a simple 'socket'.
 *
 * Extension binaries will more commonly set the path to an extension manager
 * socket. Alias the long switch name to 'socket' for an easier UX.
 *
 * We include timeout and interval, where the 'extensions_' prefix is removed
 * in the alias since we are already within the context of an extension.
 */
EXTENSION_FLAG_ALIAS(socket, extensions_socket);
EXTENSION_FLAG_ALIAS(timeout, extensions_timeout);
EXTENSION_FLAG_ALIAS(interval, extensions_interval);

/// A Dispatcher service thread that watches an ExtensionManagerHandler.
class ExtensionWatcher : public InternalRunnable {
 public:
  virtual ~ExtensionWatcher() = default;
  ExtensionWatcher(const std::string& path,
                   size_t interval,
                   bool fatal,
                   RouteUUID uuid);
  ExtensionWatcher(const std::string& path, size_t interval, bool fatal);

 public:
  /// The Dispatcher thread entry point.
  void start() override;

  /// Perform health checks.
  virtual void watch();

 protected:
  /// Exit the extension process with a fatal if the ExtensionManager dies.
  void exitFatal(int return_code = 1);

 protected:
  /// The UNIX domain socket path for the ExtensionManager.
  std::string path_;

  /// The internal in milliseconds to ping the ExtensionManager.
  size_t interval_;

  /// If the ExtensionManager socket is closed, should the extension exit.
  bool fatal_;

  /// Optional uuid used to monitor if socket is registered on with extension
  /// core
  boost::optional<RouteUUID> uuid_;
};

class ExtensionManagerWatcher : public ExtensionWatcher {
 public:
  ExtensionManagerWatcher(const std::string& path, size_t interval)
      : ExtensionWatcher(path, interval, false) {}

  /// The Dispatcher thread entry point.
  void start() override;

  /// Start a specialized health check for an ExtensionManager.
  void watch() override;

 private:
  /// Allow extensions to fail for several intervals.
  std::map<RouteUUID, size_t> failures_;
};

Status applyExtensionDelay(std::function<Status(bool& stop)> predicate) {
  // Make sure the extension manager path exists, and is writable.
  size_t delay = 0;
  // The timeout is given in seconds, but checked interval is microseconds.
  size_t timeout = atoi(FLAGS_extensions_timeout.c_str()) * 1000;
  if (timeout < kExtensionInitializeLatency * 10) {
    timeout = kExtensionInitializeLatency * 10;
  }

  Status status;
  do {
    bool stop = false;
    status = predicate(stop);
    if (stop || status.ok() || shutdownRequested()) {
      break;
    }

    // Increase the total wait detail.
    delay += kExtensionInitializeLatency;
    sleepFor(kExtensionInitializeLatency);
  } while (delay < timeout);
  return status;
}

Status extensionPathActive(const std::string& path, bool use_timeout = false) {
  return applyExtensionDelay(([path, &use_timeout](bool& stop) {
    if (socketExists(path)) {
      try {
        // Create a client with a 10-second receive timeout.
        ExtensionManagerClient client(path, 10);
        auto status = client.ping();
        return Status::success();
      } catch (const std::exception& /* e */) {
        // Path might exist without a connected extension or extension manager.
      }
    }
    // Only check active once if this check does not allow a timeout.
    if (!use_timeout) {
      stop = true;
    }
    return Status(1, "Extension socket not available: " + path);
  }));
}

ExtensionWatcher::ExtensionWatcher(const std::string& path,
                                   size_t interval,
                                   bool fatal,
                                   RouteUUID uuid)
    : ExtensionWatcher(path, interval, fatal) {
  uuid_ = uuid;
}

ExtensionWatcher::ExtensionWatcher(const std::string& path,
                                   size_t interval,
                                   bool fatal)
    : InternalRunnable("ExtensionWatcher"),
      path_(path),
      interval_(interval),
      fatal_(fatal) {
  // Set the interval to a minimum of 200 milliseconds.
  interval_ = (interval_ < 200) ? 200 : interval_;
}

void ExtensionWatcher::start() {
  // Watch the manager, if the socket is removed then the extension will die.
  // A check for sane paths and activity is applied before the watcher
  // service is added and started.
  while (!interrupted()) {
    watch();
    pause(std::chrono::milliseconds(interval_));
  }
}

void ExtensionManagerWatcher::start() {
  // Watch each extension.
  while (!interrupted()) {
    watch();
    pause(std::chrono::milliseconds(interval_));
  }

  // When interrupted, request each extension tear down.
  const auto uuids = RegistryFactory::get().routeUUIDs();
  for (const auto& uuid : uuids) {
    try {
      auto path = getExtensionSocket(uuid);
      ExtensionClient client(path);
      client.shutdown();
    } catch (const std::exception& /* e */) {
      VLOG(1) << "Extension UUID " << uuid << " shutdown request failed";
      continue;
    }
  }
}

void ExtensionWatcher::exitFatal(int return_code) {
  // Exit the extension.
  // We will save the wanted return code and raise an interrupt.
  // This interrupt will be handled by the main thread then join the watchers.
  requestShutdown(return_code);
}

void ExtensionWatcher::watch() {
  // Attempt to ping the extension core.
  // This does NOT use pingExtension to avoid the latency checks applied.
  Status status;
  bool core_sane = true;
  if (socketExists(path_)) {
    try {
      if (uuid_) {
        // Check we are still registered with the osquery core by getting
        // available extensions
        ExtensionList extensionList;
        status = getExtensions(extensionList);
        if (status.getCode() != (int)ExtensionCode::EXT_SUCCESS && fatal_) {
          LOG(ERROR) << "Extension watcher failed to get extensions: "
                     << status.getMessage();
          exitFatal();
        } else if (extensionList.find(uuid_.get()) == extensionList.end() &&
                   fatal_) {
          LOG(ERROR) << "Extension not registered with osquery core";
          exitFatal();
        }
      } else {
        // Ping the extension manager to check it's still there
        ExtensionManagerClient client(path_);
        status = client.ping();
        if (status.getCode() != (int)ExtensionCode::EXT_SUCCESS && fatal_) {
          // The core may be healthy but return a failed ping status.
          LOG(ERROR) << "Extension watcher ping failed: "
                     << status.getMessage();
          exitFatal();
        }
      }
    } catch (const std::exception& /* e */) {
      core_sane = false;
    }
  } else {
    // The previously-writable extension socket is not usable.
    core_sane = false;
  }

  if (!core_sane) {
    LOG(INFO) << "Extension watcher ending: osquery core has gone away";
    exitFatal(0);
  }
}

void ExtensionManagerWatcher::watch() {
  // Watch the set of extensions, if the socket is removed then the extension
  // will be deregistered.
  const auto uuids = RegistryFactory::get().routeUUIDs();

  Status status;
  for (const auto& uuid : uuids) {
    auto path = getExtensionSocket(uuid);
    auto exists = socketExists(path);

    if (!exists.ok() && failures_[uuid] == 0) {
      // If there was never a failure then this is the first attempt.
      // Allow the extension to be latent and respect the autoload timeout.
      VLOG(1) << "Extension UUID " << uuid << " initial check failed";
      exists = extensionPathActive(path, true);
    }

    // All extensions will have a single failure (and odd use of the counting).
    // If failures get to 2 then the extension will be removed.
    failures_[uuid] = 1;
    if (exists.ok()) {
      try {
        ExtensionClient client(path);
        // Ping the extension until it goes down.
        status = client.ping();
      } catch (const std::exception& /* e */) {
        failures_[uuid] += 1;
        continue;
      }
    } else {
      // Immediate fail non-writable paths.
      failures_[uuid] += 1;
      continue;
    }

    if (status.getCode() != (int)ExtensionCode::EXT_SUCCESS) {
      LOG(INFO) << "Extension UUID " << uuid << " ping failed";
      failures_[uuid] += 1;
    } else {
      failures_[uuid] = 1;
    }
  }

  for (const auto& uuid : failures_) {
    if (uuid.second > 1) {
      LOG(INFO) << "Extension UUID " << uuid.first << " has gone away";
      RegistryFactory::get().removeBroadcast(uuid.first);
      failures_[uuid.first] = 1;
    }
  }
}

void initShellSocket(const std::string& homedir) {
  if (FLAGS_disable_extensions) {
    return;
  }

  if (!Flag::isDefault("extensions_socket")) {
    return;
  }

  if (isPlatform(PlatformType::TYPE_WINDOWS)) {
    osquery::FLAGS_extensions_socket = "\\\\.\\pipe\\shell.em";
  } else {
    osquery::FLAGS_extensions_socket =
        (fs::path(homedir) / "shell.em").make_preferred().string();
  }

  if (extensionPathActive(FLAGS_extensions_socket, false) ||
      !socketExists(FLAGS_extensions_socket, true)) {
    // If there is an existing shell using this socket, or the socket cannot
    // be used (another user using the same path?)
    FLAGS_extensions_socket += std::to_string((uint16_t)rand());
  }
}

std::set<std::string> loadExtensions() {
  // Disabling extensions will disable autoloading.
  if (FLAGS_disable_extensions) {
    return {};
  }

  // Optionally autoload extensions, sanitize the binary path and inform
  // the osquery watcher to execute the extension when started.
  return loadExtensions(
      fs::path(FLAGS_extensions_autoload).make_preferred().string());
}

static bool isFileSafe(std::string& path, ExtendableType type) {
  boost::trim(path);
  // A 'type name' may be used in verbose log output.
  std::string type_name =
      ((type == ExtendableType::EXTENSION) ? "extension" : "module");
  if (path.size() == 0 || path[0] == '#' || path[0] == ';') {
    return false;
  }

  // Resolve acceptable extension binaries from autoload paths.
  if (isDirectory(path).ok()) {
    VLOG(1) << "Cannot autoload " << type_name << " from directory: " << path;
    return false;
  }

  std::set<std::string> exts;
  if (isPlatform(PlatformType::TYPE_LINUX)) {
    exts = kFileExtensions.at(PlatformType::TYPE_LINUX).at(type);
  } else if (isPlatform(PlatformType::TYPE_OSX)) {
    exts = kFileExtensions.at(PlatformType::TYPE_OSX).at(type);
  } else {
    exts = kFileExtensions.at(PlatformType::TYPE_WINDOWS).at(type);
  }

  // Only autoload file which were safe at the time of discovery.
  // If the binary later becomes unsafe (permissions change) then it will fail
  // to reload if a reload is ever needed.
  fs::path extendable(path);
  // Set the output sanitized path.
  path = extendable.string();
  if (!pathExists(path).ok()) {
    LOG(WARNING) << type_name << " doesn't exist at: " << path;
    return false;
  }
  if (!safePermissions(extendable.parent_path().string(), path, true)) {
    LOG(WARNING) << "Will not autoload " << type_name
                 << " with unsafe directory permissions: " << path;
    return false;
  }

  if (exts.find(extendable.extension().string()) == exts.end()) {
    std::string ends = osquery::join(exts, "', '");
    LOG(WARNING) << "Will not autoload " << type_name
                 << " not ending in one of '" << ends << "': " << path;
    return false;
  }

  VLOG(1) << "Found autoloadable " << type_name << ": " << path;
  return true;
}

std::set<std::string> loadExtensions(const std::string& loadfile) {
  std::set<std::string> autoload_binaries;
  if (!FLAGS_extension.empty()) {
    // This is a shell-only development flag for quickly loading/using a single
    // extension. It bypasses the safety check.
    autoload_binaries.insert(FLAGS_extension);
  }

  std::string autoload_paths;
  auto status = readFile(loadfile, autoload_paths);
  if (!status.ok()) {
    VLOG(1) << "Could not autoload extensions: " << status.what();
  }

  // The set of binaries to auto-load, after safety is confirmed.
  for (auto& path : osquery::split(autoload_paths, "\n")) {
    if (isDirectory(path)) {
      std::vector<std::string> paths;
      listFilesInDirectory(path, paths, true);
      for (auto& embedded_path : paths) {
        if (isFileSafe(embedded_path, ExtendableType::EXTENSION)) {
          autoload_binaries.insert(std::move(embedded_path));
        }
      }
    } else if (isFileSafe(path, ExtendableType::EXTENSION)) {
      autoload_binaries.insert(path);
    }
  }

  return autoload_binaries;
}

Status startExtension(const std::string& name, const std::string& version) {
  return startExtension(name, version, "0.0.0");
}

Status startExtension(const std::string& name,
                      const std::string& version,
                      const std::string& min_sdk_version) {
  // Tell the registry that this is an extension.
  // When a broadcast is requested this registry should not send core plugins.
  RegistryFactory::get().setExternal();

  auto status = startExtension(
      FLAGS_extensions_socket, name, version, min_sdk_version, kSDKVersion);
  if (!status.ok()) {
    // If the extension failed to start then the EM is most likely unavailable.
    return status;
  }
  return Status(0);
}

Status startExtension(const std::string& manager_path,
                      const std::string& name,
                      const std::string& version,
                      const std::string& min_sdk_version,
                      const std::string& sdk_version) {
  // Make sure the extension manager path exists, and is writable.
  auto status = extensionPathActive(manager_path, true);
  if (!status.ok()) {
    return status;
  }

  // The Registry broadcast is used as the ExtensionRegistry.
  auto broadcast = RegistryFactory::get().getBroadcast();
  // The extension will register and provide name, version, sdk details.
  ExtensionInfo info;
  info.name = name;
  info.version = version;
  info.sdk_version = sdk_version;
  info.min_sdk_version = min_sdk_version;

  // If registration is successful, we will also request the manager's options.
  OptionList options;
  // Register the extension's registry broadcast with the manager.
  RouteUUID uuid = 0;
  try {
    ExtensionManagerClient client(manager_path);
    status = client.registerExtension(info, broadcast, uuid);
    // The main reason for a failed registry is a duplicate extension name
    // (the extension process is already running), or the extension broadcasts
    // a duplicate registry item.
    if (status.getCode() == (int)ExtensionCode::EXT_FAILED) {
      return status;
    }
    // Request the core options, mainly to set the active registry plugins for
    // logger and config.
    options = client.options();
  } catch (const std::exception& e) {
    return Status(1, "Extension register failed: " + std::string(e.what()));
  }

  // Now that the UUID is known, try to clean up stale socket paths.
  auto extension_path = getExtensionSocket(uuid, manager_path);

  // Latency converted to milliseconds, used as a thread interruptible.
  auto latency = atoi(FLAGS_extensions_interval.c_str()) * 1000;

  // Register the watcher with it's uuid
  status = startExtensionWatcher(manager_path, latency, true, uuid);
  if (!status.ok()) {
    // If the threaded watcher fails to start, fail the extension.
    return status;
  }

  status = socketExists(extension_path, true);
  if (!status) {
    return status;
  }

  // Set the active config and logger plugins. The core will arbitrate if the
  // plugins are not available in the extension's local registry.
  auto& rf = RegistryFactory::get();
  rf.setActive("config", options["config_plugin"].value);
  rf.setActive("logger", options["logger_plugin"].value);
  rf.setActive("distributed", options["distributed_plugin"].value);
  // Set up all lazy registry plugins and the active config/logger plugin.
  rf.setUp();

  // Start the extension's Thrift server
  Dispatcher::addService(std::make_shared<ExtensionRunner>(manager_path, uuid));
  VLOG(1) << "Extension (" << name << ", " << uuid << ", " << version << ", "
          << sdk_version << ") registered";
  return Status(0, std::to_string(uuid));
}

Status ExternalSQLPlugin::query(const std::string& query,
                                QueryData& results,
                                bool use_cache) const {
  static_cast<void>(use_cache);
  // Make sure the extension path exists, and is writable.
  auto status = extensionPathActive(FLAGS_extensions_socket);
  if (!status.ok()) {
    return status;
  }

  try {
    ExtensionManagerClient client(FLAGS_extensions_socket);
    status = client.query(query, results);
  } catch (const std::exception& e) {
    return Status(1, "Extension call failed: " + std::string(e.what()));
  }

  return status;
}

Status ExternalSQLPlugin::getQueryColumns(const std::string& query,
                                          TableColumns& columns) const {
  // Make sure the extension path exists, and is writable.
  auto status = extensionPathActive(FLAGS_extensions_socket);
  if (!status.ok()) {
    return status;
  }

  QueryData qd;
  try {
    ExtensionManagerClient client(FLAGS_extensions_socket);
    status = client.getQueryColumns(query, qd);
  } catch (const std::exception& e) {
    return Status(1, "Extension call failed: " + std::string(e.what()));
  }

  // Translate response map: {string: string} to a vector: pair(name, type).
  for (const auto& column : qd) {
    for (const auto& col : column) {
      columns.push_back(std::make_tuple(
          col.first, columnTypeName(col.second), ColumnOptions::DEFAULT));
    }
  }

  return status;
}

Status pingExtension(const std::string& path) {
  if (FLAGS_disable_extensions) {
    return Status(1, "Extensions disabled");
  }

  // Make sure the extension path exists, and is writable.
  auto status = extensionPathActive(path);
  if (!status.ok()) {
    return status;
  }

  try {
    ExtensionClient client(path);
    status = client.ping();
  } catch (const std::exception& e) {
    return Status(1, "Extension call failed: " + std::string(e.what()));
  }

  return Status(0, status.getMessage());
}

Status getExtensions(ExtensionList& extensions) {
  if (FLAGS_disable_extensions) {
    return Status(1, "Extensions disabled");
  }
  return getExtensions(FLAGS_extensions_socket, extensions);
}

Status getExtensions(const std::string& manager_path,
                     ExtensionList& extensions) {
  // Make sure the extension path exists, and is writable.
  auto status = extensionPathActive(manager_path);
  if (!status.ok()) {
    return status;
  }

  ExtensionList ext_list;
  try {
    ExtensionManagerClient client(manager_path);
    ext_list = client.extensions();
  } catch (const std::exception& e) {
    return Status(1, "Extension call failed: " + std::string(e.what()));
  }

  // Add the extension manager to the list called (core).
  extensions[0] = {"core", kVersion, "0.0.0", kSDKVersion};

  // Convert from Thrift-internal list type to RouteUUID/ExtensionInfo type.
  for (const auto& ext : ext_list) {
    extensions[ext.first] = {ext.second.name,
                             ext.second.version,
                             ext.second.min_sdk_version,
                             ext.second.sdk_version};
  }

  return Status::success();
}

Status callExtension(const RouteUUID uuid,
                     const std::string& registry,
                     const std::string& item,
                     const PluginRequest& request,
                     PluginResponse& response) {
  if (FLAGS_disable_extensions) {
    return Status(1, "Extensions disabled");
  }
  return callExtension(
      getExtensionSocket(uuid), registry, item, request, response);
}

Status callExtension(const std::string& extension_path,
                     const std::string& registry,
                     const std::string& item,
                     const PluginRequest& request,
                     PluginResponse& response) {
  // Make sure the extension manager path exists, and is writable.
  auto status = extensionPathActive(extension_path);
  if (!status.ok()) {
    return status;
  }

  try {
    ExtensionClient client(extension_path);
    status = client.call(registry, item, request, response);
  } catch (const std::exception& e) {
    return Status(1, "Extension call failed: " + std::string(e.what()));
  }

  return status;
}

Status startExtensionWatcher(const std::string& manager_path,
                             size_t interval,
                             bool fatal,
                             RouteUUID uuid) {
  // Make sure the extension manager path exists, and is writable.
  auto status = extensionPathActive(manager_path, true);
  if (!status.ok()) {
    return status;
  }

  // Start a extension watcher, if the manager dies, so should we.
  Dispatcher::addService(
      std::make_shared<ExtensionWatcher>(manager_path, interval, fatal, uuid));
  return Status::success();
}

Status startExtensionManager() {
  if (FLAGS_disable_extensions) {
    return Status(1, "Extensions disabled");
  }
  return startExtensionManager(FLAGS_extensions_socket);
}

Status startExtensionManager(const std::string& manager_path) {
  // Check if the socket location is ready for a new Thrift server.
  // We expect the path to be invalid or a removal attempt to succeed.
  auto status = socketExists(manager_path, true);
  if (!status.ok()) {
    return status;
  }

  // Seconds converted to milliseconds, used as a thread interruptible.
  auto latency = atoi(FLAGS_extensions_interval.c_str()) * 1000;
  // Start a extension manager watcher, to monitor all registered extensions.
  status = Dispatcher::addService(
      std::make_shared<ExtensionManagerWatcher>(manager_path, latency));

  if (!status.ok()) {
    return status;
  }

  // Start the extension manager thread.
  status = Dispatcher::addService(
      std::make_shared<ExtensionManagerRunner>(manager_path));

  if (!status.ok()) {
    return status;
  }

  // The shell or daemon flag configuration may require an extension.
  if (!FLAGS_extensions_require.empty()) {
    bool waited = false;
    auto extensions = osquery::split(FLAGS_extensions_require, ",");
    for (const auto& extension : extensions) {
      status = applyExtensionDelay(([extension, &waited](bool& stop) {
        ExtensionList registered_extensions;
        if (getExtensions(registered_extensions).ok()) {
          for (const auto& existing : registered_extensions) {
            if (existing.second.name == extension) {
              return pingExtension(getExtensionSocket(existing.first));
            }
          }
        }

        if (waited) {
          // If we have already waited for the timeout period, stop early.
          stop = true;
        }
        return Status(
            1, "Required extension not found or not loaded: " + extension);
      }));

      // A required extension was not loaded.
      waited = true;
      if (!status.ok()) {
        LOG(WARNING) << status.getMessage();
        return status;
      }
    }
  }

  return Status::success();
}
} // namespace osquery

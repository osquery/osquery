/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <map>
#include <set>
#include <string>
#include <tuple>
#include <vector>

#include <boost/algorithm/string/trim.hpp>

#include <osquery/core.h>
#include <osquery/extensions/interface.h>
#include <osquery/filesystem/fileops.h>
#include <osquery/flagalias.h>
#include <osquery/logger.h>
#include <osquery/process/process.h>
#include <osquery/registry.h>
#include <osquery/utils/config/default_paths.h>
#include <osquery/utils/info/version.h>

namespace fs = boost::filesystem;

namespace osquery {

// Millisecond latency between initializing manager pings.
const size_t kExtensionInitializeLatency = 20;

CLI_FLAG(bool, disable_extensions, false, "Disable extension API");

CLI_FLAG(string,
         extensions_socket,
         OSQUERY_SOCKET "osquery.em",
         "Path to the extensions UNIX domain socket");

CLI_FLAG(string,
         extensions_timeout,
         "3",
         "Seconds to wait for autoloaded extensions");

CLI_FLAG(string,
         extensions_interval,
         "3",
         "Seconds delay between connectivity checks");

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
    if (stop || status.ok()) {
      break;
    }

    // Increase the total wait detail.
    delay += kExtensionInitializeLatency;
    sleepFor(kExtensionInitializeLatency);
  } while (delay < timeout);
  return status;
}

Status extensionPathActive(const std::string& path, bool use_timeout) {
  return applyExtensionDelay(([path, &use_timeout](bool& stop) {
    if (socketExists(path)) {
      try {
        // Create a client with a 10-second receive timeout.
        ExtensionManagerClient client(path, 10 * 1000);
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

  // Convert from Thrift-internal list type to RouteUUID/ExtenionInfo type.
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
} // namespace osquery

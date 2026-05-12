/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <devinfo.h>

#include <cctype>
#include <map>
#include <sstream>
#include <string>

#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>

namespace osquery {
namespace tables {

namespace {

/// Parse a key=value attribute string from devinfo's pnpinfo / location
/// outputs.  Values are unquoted hex literals or short tokens.
std::map<std::string, std::string> parsePnpInfo(const char* s) {
  std::map<std::string, std::string> out;
  if (s == nullptr) {
    return out;
  }
  std::string input(s);
  size_t i = 0;
  while (i < input.size()) {
    while (i < input.size() &&
           std::isspace(static_cast<unsigned char>(input[i]))) {
      i++;
    }
    if (i >= input.size()) {
      break;
    }
    auto eq = input.find('=', i);
    if (eq == std::string::npos) {
      break;
    }
    std::string key = input.substr(i, eq - i);
    i = eq + 1;
    auto end = i;
    while (end < input.size() &&
           !std::isspace(static_cast<unsigned char>(input[end]))) {
      end++;
    }
    out[key] = input.substr(i, end - i);
    i = end;
  }
  return out;
}

/// Trim a leading "0x" off a string so we can re-prepend a consistent form.
std::string stripHexPrefix(const std::string& v) {
  if (v.size() > 2 && v[0] == '0' && (v[1] == 'x' || v[1] == 'X')) {
    return v.substr(2);
  }
  return v;
}

struct WalkContext {
  QueryData* results;
};

int devWalker(struct devinfo_dev* dev, void* arg) {
  auto* ctx = static_cast<WalkContext*>(arg);

  // We only care about PCI children -- detect via parent name starting with
  // "pci" or via pnpinfo containing a PCI class field.
  auto pnp = parsePnpInfo(dev->dd_pnpinfo);

  // Skip nodes that have no PCI vendor info -- those are not PCI devs.
  if (pnp.find("vendor") == pnp.end() || pnp.find("device") == pnp.end() ||
      pnp.find("class") == pnp.end()) {
    devinfo_foreach_device_child(dev, devWalker, arg);
    return 0;
  }

  Row r;

  // dd_name is the driver-assigned device name (e.g. "hostb0", "em0").
  // dd_location is bus-specific ("pci0:0:0:0" for PCI).
  std::string name = dev->dd_name ? dev->dd_name : "";
  std::string loc = dev->dd_location ? dev->dd_location : "";

  r["pci_slot"] = loc;

  std::string vendor_id = stripHexPrefix(pnp["vendor"]);
  std::string model_id = stripHexPrefix(pnp["device"]);
  std::string pci_class = stripHexPrefix(pnp["class"]);

  // Normalize to lowercase hex without 0x prefix, padded to 4 chars for
  // vendor/model and 6 for class (matches Linux representation).
  auto pad = [](std::string v, size_t width) {
    for (auto& c : v) {
      c = std::tolower(static_cast<unsigned char>(c));
    }
    if (v.size() < width) {
      v.insert(0, width - v.size(), '0');
    }
    return v;
  };

  r["vendor_id"] = pad(vendor_id, 4);
  r["model_id"] = pad(model_id, 4);
  r["pci_class"] = pad(pci_class, 6);

  // No vendor/model name resolution on FreeBSD without pciconf -lv parsing;
  // leave the human-readable strings empty for now.
  r["vendor"] = "";
  r["model"] = "";

  // Driver is the dev name with the unit number stripped.
  std::string driver = name;
  while (!driver.empty() &&
         std::isdigit(static_cast<unsigned char>(driver.back()))) {
    driver.pop_back();
  }
  r["driver"] = driver;

  ctx->results->push_back(r);

  devinfo_foreach_device_child(dev, devWalker, arg);
  return 0;
}

} // namespace

QueryData genPCIDevices(QueryContext& context) {
  QueryData results;

  if (devinfo_init() != 0) {
    LOG(WARNING) << "pci_devices: devinfo_init failed";
    return results;
  }

  WalkContext ctx{&results};
  struct devinfo_dev* root = devinfo_handle_to_device(DEVINFO_ROOT_DEVICE);
  if (root != nullptr) {
    devinfo_foreach_device_child(root, devWalker, &ctx);
  }

  devinfo_free();
  return results;
}

} // namespace tables
} // namespace osquery

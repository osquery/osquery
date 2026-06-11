/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <libusb.h>

#include <cstdio>
#include <string>

#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>

namespace osquery {
namespace tables {

namespace {

/// Format a 16-bit USB id as zero-padded lowercase hex (no 0x prefix).
std::string hex4(uint16_t v) {
  char buf[8];
  std::snprintf(buf, sizeof(buf), "%04x", v);
  return std::string(buf);
}

/// Read a USB string descriptor by index into a C++ string.
std::string readStringDescriptor(libusb_device_handle* h, uint8_t index) {
  if (h == nullptr || index == 0) {
    return "";
  }
  unsigned char buf[256];
  int rc = libusb_get_string_descriptor_ascii(h, index, buf, sizeof(buf));
  if (rc <= 0) {
    return "";
  }
  return std::string(reinterpret_cast<char*>(buf), static_cast<size_t>(rc));
}

} // namespace

QueryData genUSBDevices(QueryContext& context) {
  QueryData results;

  libusb_context* ctx = nullptr;
  if (libusb_init(&ctx) != 0) {
    LOG(WARNING) << "usb_devices: libusb_init failed";
    return results;
  }

  libusb_device** list = nullptr;
  ssize_t n = libusb_get_device_list(ctx, &list);
  if (n < 0) {
    libusb_exit(ctx);
    return results;
  }

  for (ssize_t i = 0; i < n; i++) {
    libusb_device* dev = list[i];
    struct libusb_device_descriptor desc;
    if (libusb_get_device_descriptor(dev, &desc) != 0) {
      continue;
    }

    Row r;
    r["usb_address"] = std::to_string(libusb_get_device_address(dev));
    r["usb_port"] = std::to_string(libusb_get_port_number(dev));
    r["vendor_id"] = hex4(desc.idVendor);
    r["model_id"] = hex4(desc.idProduct);

    // Version: bcdDevice is the device release number, BCD-encoded.
    {
      char ver[16];
      std::snprintf(ver,
                    sizeof(ver),
                    "%x.%02x",
                    (desc.bcdDevice >> 8) & 0xff,
                    desc.bcdDevice & 0xff);
      r["version"] = ver;
    }

    r["class"] = std::to_string(desc.bDeviceClass);
    r["subclass"] = std::to_string(desc.bDeviceSubClass);
    r["protocol"] = std::to_string(desc.bDeviceProtocol);

    // Hub root devices are not removable in the USB sense; everything else
    // we treat as removable by default on FreeBSD.
    r["removable"] = (desc.bDeviceClass == LIBUSB_CLASS_HUB) ? "0" : "1";

    // Optional descriptor strings -- requires opening the device, which may
    // fail without root.  Tolerate failure quietly.
    libusb_device_handle* h = nullptr;
    if (libusb_open(dev, &h) == 0 && h != nullptr) {
      r["vendor"] = readStringDescriptor(h, desc.iManufacturer);
      r["model"] = readStringDescriptor(h, desc.iProduct);
      r["serial"] = readStringDescriptor(h, desc.iSerialNumber);
      libusb_close(h);
    } else {
      r["vendor"] = "";
      r["model"] = "";
      r["serial"] = "";
    }

    results.push_back(r);
  }

  libusb_free_device_list(list, 1);
  libusb_exit(ctx);
  return results;
}

} // namespace tables
} // namespace osquery

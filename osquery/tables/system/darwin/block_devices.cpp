/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <DiskArbitration/DADisk.h>
#include <DiskArbitration/DASession.h>

#include <boost/optional.hpp>

#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/tables/system/darwin/block_devices.h>
#include <osquery/utils/conversions/darwin/cfstring.h>

#include <cstring>

namespace osquery::tables {

namespace {

const std::string kIOMediaClassName{"IOMedia"};

template <typename ResourceType>
class IoResourceDeleter final {
 public:
  using pointer = ResourceType;

  void operator()(pointer p) {
    IOObjectRelease(p);
  }
};

template <typename PointeeType>
class CFReleaseDeleter final {
 public:
  using pointer = PointeeType*;

  void operator()(pointer p) {
    if (p == nullptr) {
      return;
    }

    CFRelease(p);
  }
};

using UniqueIoIterator =
    std::unique_ptr<io_iterator_t, IoResourceDeleter<io_iterator_t>>;

using UniqueIoObject =
    std::unique_ptr<io_object_t, IoResourceDeleter<io_object_t>>;

using UniqueMutableDictionary =
    std::unique_ptr<struct CF_BRIDGED_MUTABLE_TYPE(NSMutableDictionary)
                        __CFDictionary,
                    CFReleaseDeleter<struct CF_BRIDGED_MUTABLE_TYPE(
                        NSMutableDictionary) __CFDictionary>>;

using UniqueConstDictionary =
    std::unique_ptr<const struct CF_BRIDGED_TYPE(NSDictionary) __CFDictionary,
                    CFReleaseDeleter<const struct CF_BRIDGED_TYPE(NSDictionary)
                                         __CFDictionary>>;

using UniqueDASession =
    std::unique_ptr<struct CF_BRIDGED_TYPE(id) __DASession,
                    CFReleaseDeleter<struct CF_BRIDGED_TYPE(id) __DASession>>;

using UniqueDADisk =
    std::unique_ptr<struct CF_BRIDGED_TYPE(id) __DADisk,
                    CFReleaseDeleter<struct CF_BRIDGED_TYPE(id) __DADisk>>;

boost::optional<UniqueIoIterator> getIoMediaIterator() {
  auto matching = IOServiceMatching(kIOMediaClassName.c_str());
  if (matching == nullptr) {
    return boost::none;
  }

  io_iterator_t it;

  auto kr = IOServiceGetMatchingServices(kIOMasterPortDefault, matching, &it);
  if (kr != KERN_SUCCESS) {
    return boost::none;
  }

  return UniqueIoIterator(it);
}

boost::optional<UniqueIoObject> getNextIoMediaObject(
    const UniqueIoIterator& io_media_iterator) {
  auto device = IOIteratorNext(io_media_iterator.get());
  if (device == 0) {
    return boost::none;
  }

  return UniqueIoObject(device);
}

boost::optional<UniqueMutableDictionary> getDiskPropertyDictionary(
    const UniqueIoObject& device) {
  UniqueMutableDictionary dictionary;

  {
    CFMutableDictionaryRef properties = nullptr;

    auto error = IORegistryEntryCreateCFProperties(
        device.get(), &properties, kCFAllocatorDefault, kNilOptions);

    if (error != KERN_SUCCESS) {
      return boost::none;
    }

    dictionary.reset(properties);
  }

  return dictionary;
}

template <typename DictionaryType>
boost::optional<std::string> getDiskPropertyStringValue(
    const DictionaryType& dictionary, const std::string& key_name) {
  static_assert(std::is_same<DictionaryType, UniqueMutableDictionary>::value ||
                    std::is_same<DictionaryType, UniqueConstDictionary>::value,
                "Invalid type passed to DictionaryType");

  auto cstr_ptr = CFStringCreateWithCString(
      kCFAllocatorDefault, key_name.c_str(), kCFStringEncodingUTF8);

  if (cstr_ptr == nullptr) {
    return boost::none;
  }

  auto value_ptr = CFDictionaryGetValue(dictionary.get(), cstr_ptr);
  CFRelease(cstr_ptr);

  if (value_ptr == nullptr) {
    return boost::none;
  }

  if (CFGetTypeID(value_ptr) != CFStringGetTypeID()) {
    return boost::none;
  }

  return stringFromCFString(static_cast<CFStringRef>(value_ptr));
}

template <typename DictionaryType>
boost::optional<bool> getDiskPropertyBooleanValue(
    const DictionaryType& dictionary, const std::string& key_name) {
  static_assert(std::is_same<DictionaryType, UniqueMutableDictionary>::value ||
                    std::is_same<DictionaryType, UniqueConstDictionary>::value,
                "Invalid type passed to DictionaryType");

  auto cstr_ptr = CFStringCreateWithCString(
      kCFAllocatorDefault, key_name.c_str(), kCFStringEncodingUTF8);

  if (cstr_ptr == nullptr) {
    return boost::none;
  }

  auto value_ptr = CFDictionaryGetValue(dictionary.get(), cstr_ptr);
  CFRelease(cstr_ptr);

  if (value_ptr == nullptr) {
    return boost::none;
  }

  if (CFGetTypeID(value_ptr) != CFBooleanGetTypeID()) {
    return boost::none;
  }

  return CFBooleanGetValue(static_cast<CFBooleanRef>(value_ptr));
}

template <typename StorageType>
boost::optional<std::uint64_t> getCFNumberValue(CFNumberRef number_ptr) {
  StorageType storage{};
  if (!CFNumberGetValue(number_ptr, CFNumberGetType(number_ptr), &storage)) {
    return boost::none;
  }

  return static_cast<std::uint64_t>(storage);
}

boost::optional<std::uint64_t> getCFNumberValue(CFNumberRef number_ptr) {
  switch (CFNumberGetType(number_ptr)) {
  case kCFNumberSInt8Type:
    return getCFNumberValue<std::int8_t>(number_ptr);

  case kCFNumberSInt16Type:
    return getCFNumberValue<std::int16_t>(number_ptr);

  case kCFNumberSInt32Type:
    return getCFNumberValue<std::int32_t>(number_ptr);

  case kCFNumberSInt64Type:
    return getCFNumberValue<std::int64_t>(number_ptr);

  case kCFNumberCharType:
    return getCFNumberValue<char>(number_ptr);

  case kCFNumberShortType:
    return getCFNumberValue<short>(number_ptr);

  case kCFNumberIntType:
    return getCFNumberValue<int>(number_ptr);

  case kCFNumberLongType:
    return getCFNumberValue<long>(number_ptr);

  case kCFNumberLongLongType:
    return getCFNumberValue<long long>(number_ptr);

  default:
    return boost::none;
  }
}

boost::optional<std::uint64_t> getDiskPropertyIntegerValue(
    const UniqueMutableDictionary& dictionary, const std::string& key_name) {
  auto cstr_ptr = CFStringCreateWithCString(
      kCFAllocatorDefault, key_name.c_str(), kCFStringEncodingUTF8);

  if (cstr_ptr == nullptr) {
    return boost::none;
  }

  auto value_ptr = CFDictionaryGetValue(dictionary.get(), cstr_ptr);
  CFRelease(cstr_ptr);

  if (value_ptr == nullptr) {
    return boost::none;
  }

  if (CFGetTypeID(value_ptr) != CFNumberGetTypeID()) {
    return boost::none;
  }

  return getCFNumberValue(static_cast<CFNumberRef>(value_ptr));
}

boost::optional<std::string> getRealDiskIdentifier(const std::string& disk_id) {
  auto separator = disk_id.find('s', 4);
  if (separator == std::string::npos) {
    return boost::none;
  }

  return disk_id.substr(0, separator);
}

boost::optional<std::string> getDiskLabel(const UniqueIoObject& device) {
  io_name_t label;
  auto kr = IORegistryEntryGetName(device.get(), label);
  if (kr != KERN_SUCCESS) {
    return boost::none;
  }

  auto label_size = strnlen(label, 128);
  return std::string(label, label_size);
}

boost::optional<UniqueDASession> createDiskArbitrationSession() {
  auto session = DASessionCreate(kCFAllocatorDefault);
  if (session == nullptr) {
    return boost::none;
  }

  return UniqueDASession(session);
}

struct DiskArbitrationDetails final {
  boost::optional<std::string> opt_protocol;
  boost::optional<std::string> opt_vendor;
  boost::optional<std::string> opt_model;
};

boost::optional<UniqueDADisk> createDADisk(const UniqueDASession& da_session,
                                           const UniqueIoObject& device) {
  auto disk = DADiskCreateFromIOMedia(
      kCFAllocatorDefault, da_session.get(), device.get());
  if (disk == nullptr) {
    return boost::none;
  }

  return UniqueDADisk(disk);
}

DiskArbitrationDetails getDiskArbitrationDetails(
    const UniqueDASession& da_session, const UniqueIoObject& device) {
  auto opt_da_disk = createDADisk(da_session, device);
  if (!opt_da_disk.has_value()) {
    return {};
  }

  auto& da_disk = opt_da_disk.value();

  UniqueConstDictionary disk_copy_desc;

  {
    auto desc = DADiskCopyDescription(da_disk.get());
    if (desc == nullptr) {
      return {};
    }

    disk_copy_desc.reset(desc);
  }

  DiskArbitrationDetails da_details;
  da_details.opt_model =
      getDiskPropertyStringValue(disk_copy_desc, "DADeviceModel");

  da_details.opt_vendor =
      getDiskPropertyStringValue(disk_copy_desc, "DADeviceVendor");

  da_details.opt_protocol =
      getDiskPropertyStringValue(disk_copy_desc, "DADeviceProtocol");

  return da_details;
}

} // namespace

boost::optional<DiskInformationList> getDiskInformationList() {
  auto opt_io_media_iterator = getIoMediaIterator();
  if (!opt_io_media_iterator.has_value()) {
    LOG(ERROR) << "Failed to initialize the IO Media iterator";
    return boost::none;
  }

  auto& io_media_iterator = opt_io_media_iterator.value();

  auto opt_da_session = createDiskArbitrationSession();
  if (!opt_da_session.has_value()) {
    LOG(ERROR) << "Failed to initialize the Disk Arbitration API";
    return boost::none;
  }

  auto& da_session = opt_da_session.value();

  DiskInformationList disk_info_list;

  for (;;) {
    auto opt_device = getNextIoMediaObject(io_media_iterator);
    if (!opt_device.has_value()) {
      break;
    }

    const auto& device = opt_device.value();

    auto opt_properties = getDiskPropertyDictionary(device);
    if (!opt_properties.has_value()) {
      LOG(ERROR) << "Failed to acquire the properties of one the disks";
      continue;
    }

    const auto& properties = opt_properties.value();

    auto opt_disk_id = getDiskPropertyStringValue(properties, "BSD Name");
    if (!opt_disk_id.has_value()) {
      LOG(ERROR) << "Failed to acquire the name of one the disks";
      continue;
    }

    const auto& disk_id = opt_disk_id.value();

    DiskInformation disk_info = {};
    disk_info.id = disk_id;

    auto opt_whole = getDiskPropertyBooleanValue(properties, "Whole");
    if (opt_whole.has_value()) {
      const auto& is_whole_disk = opt_whole.value();

      if (!is_whole_disk) {
        auto opt_parent = getRealDiskIdentifier(disk_id);
        if (opt_parent.has_value()) {
          disk_info.parent_id = opt_parent.value();

        } else {
          LOG(ERROR)
              << "Failed to identify the parent disk of the following disk: "
              << disk_id;
        }
      }

    } else {
      LOG(ERROR)
          << "Failed to acquire the Whole property of the following disk: "
          << disk_id;
    }

    auto opt_disk_uuid = getDiskPropertyStringValue(properties, "UUID");
    if (opt_disk_uuid.has_value()) {
      disk_info.uuid = opt_disk_uuid.value();
    } else {
      LOG(ERROR) << "Failed to acquire the UUID of the following disk: "
                 << disk_id;
    }

    auto opt_size = getDiskPropertyIntegerValue(properties, "Size");
    if (opt_size.has_value()) {
      disk_info.size = opt_size.value();
    } else {
      LOG(ERROR) << "Failed to acquire the size of the following disk: "
                 << disk_id;
    }

    auto opt_preferred_block_size =
        getDiskPropertyIntegerValue(properties, "Preferred Block Size");
    if (opt_preferred_block_size.has_value()) {
      disk_info.preferred_block_size = opt_preferred_block_size.value();
    } else {
      LOG(ERROR) << "Failed to acquire the preferred blocks size of the "
                    "following disk: "
                 << disk_id;
    }

    auto opt_disk_label = getDiskLabel(device);
    if (opt_disk_label.has_value()) {
      disk_info.label = opt_disk_label.value();
    } else {
      LOG(ERROR) << "Failed to acquire the label of the following disk: "
                 << disk_id;
    }

    auto da_details = getDiskArbitrationDetails(da_session, device);
    if (da_details.opt_protocol.has_value()) {
      disk_info.protocol = da_details.opt_protocol.value();
    } else {
      LOG(ERROR) << "Failed to acquire the protocol of the following disk: "
                 << disk_id;
    }

    if (da_details.opt_vendor.has_value()) {
      disk_info.vendor = da_details.opt_vendor.value();
    } else {
      LOG(ERROR) << "Failed to acquire the vendor of the following disk: "
                 << disk_id;
    }

    if (da_details.opt_model.has_value()) {
      disk_info.model = da_details.opt_model.value();
    } else {
      LOG(ERROR) << "Failed to acquire the model of the following disk: "
                 << disk_id;
    }

    disk_info_list.push_back(std::move(disk_info));
  }

  return disk_info_list;
}

QueryData genBlockDevs(QueryContext& context) {
  auto opt_disk_info_list = getDiskInformationList();
  if (!opt_disk_info_list.has_value()) {
    return {};
  }

  const auto& disk_info_list = opt_disk_info_list.value();

  QueryData results;

  for (const auto& disk_info : disk_info_list) {
    Row r;
    r["name"] = SQL_TEXT("/dev/" + disk_info.id);

    auto parent =
        !disk_info.parent_id.empty() ? "/dev/" + disk_info.parent_id : "";
    r["parent"] = SQL_TEXT(parent);

    r["vendor"] = SQL_TEXT(disk_info.vendor);
    r["model"] = SQL_TEXT(disk_info.model);
    r["size"] = BIGINT(disk_info.size / disk_info.preferred_block_size);
    r["block_size"] = BIGINT(disk_info.preferred_block_size);
    r["uuid"] = SQL_TEXT(disk_info.uuid);
    r["type"] = SQL_TEXT(disk_info.protocol);
    r["label"] = SQL_TEXT(disk_info.label);

    results.push_back(std::move(r));
  }

  return results;
}
} // namespace osquery::tables

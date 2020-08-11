/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/utils/system/linux/tracing/native_event.h>

#include <osquery/utils/conversions/tryto.h>

#include <osquery/logger/logger.h>

#include <boost/filesystem/path.hpp>
#include <boost/io/detail/quoted_manip.hpp>

#include <fstream>

namespace osquery {
namespace tracing {

namespace fs = boost::filesystem;

fs::path getNativeEventFullPath(const std::string& event_path) {
  return fs::path("/sys/kernel/debug/tracing/events") / event_path;
}

NativeEvent::~NativeEvent() {
  auto const exp = enable(false);
  if (exp.isError()) {
    LOG(WARNING) << "Disabling system event " << event_path_
                 << " failed: " << exp.getError().getMessage();
  }
}

NativeEvent::NativeEvent(NativeEvent&& other)
    : id_(other.id_), event_path_(std::move(other.event_path_)) {
  other.id_ = -1;
}

NativeEvent& NativeEvent::operator=(NativeEvent&& other) {
  std::swap(id_, other.id_);
  std::swap(event_path_, other.event_path_);
  return *this;
}

Expected<NativeEvent, NativeEvent::Error> NativeEvent::load(
    std::string event_path) {
  auto instance = NativeEvent(std::move(event_path));
  auto exp = instance.enable(true);
  if (exp.isError()) {
    return exp.takeError();
  }
  return Expected<NativeEvent, NativeEvent::Error>(std::move(instance));
}

SystemEventId NativeEvent::id() const {
  return id_;
}

NativeEvent::NativeEvent(std::string event_path)
    : event_path_(std::move(event_path)) {}

namespace {

Expected<int, NativeEvent::Error> extractIdFromTheSystem(
    fs::path const& full_event_path) {
  auto const id_path = full_event_path / "id";
  auto id_in =
      std::fstream(id_path.native(), std::ios_base::in | std::ios_base::binary);
  auto id_str = std::string{};
  if (id_in.is_open()) {
    id_in >> id_str;
  }
  if (!id_in.is_open() || id_in.fail()) {
    return createError(NativeEvent::Error::System)
           << "Could not open linux event id file "
           << boost::io::quoted(id_path.string());
  }
  auto id_exp = tryTo<SystemEventId>(id_str);
  if (id_exp.isError()) {
    return createError(NativeEvent::Error::System)
           << "Could not parse linux event id from the string "
           << boost::io::quoted(id_str);
  }
  return id_exp.get();
}

} // namespace

bool NativeEvent::isEnabled() const {
  return id_ >= 0;
}

ExpectedSuccess<NativeEvent::Error> NativeEvent::enable(bool do_enable) {
  if (do_enable == isEnabled()) {
    // Nothing to do it is already enabled or disabled
    return Success{};
  }
  auto const full_event_path = getNativeEventFullPath(event_path_);
  auto const event_enable_path = full_event_path / "enable";
  auto event_enable_out = std::fstream(
      event_enable_path.native(), std::ios_base::out | std::ios_base::binary);
  if (event_enable_out.is_open()) {
    auto const buf = do_enable ? "1" : "0";
    event_enable_out << buf;
  }
  if (!event_enable_out.is_open() || event_enable_out.fail()) {
    auto const action = do_enable ? "enable" : "disable";
    return createError(Error::System)
           << "Could not " << action
           << " system event, not sufficient rights to modify file "
           << boost::io::quoted(event_enable_path.string());
  }
  if (do_enable) {
    auto id_exp = extractIdFromTheSystem(full_event_path);
    if (id_exp.isError()) {
      return createError(Error::System, id_exp.takeError())
             << "Could not retrieve event id from the system";
    }
    id_ = id_exp.take();
  } else {
    id_ = -1;
  }
  return Success{};
}

} // namespace tracing
} // namespace osquery

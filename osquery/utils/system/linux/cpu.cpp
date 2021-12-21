/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/algorithm/string.hpp>
#include <boost/io/quoted.hpp>

#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/system/linux/cpu.h>

#include <fstream>

namespace osquery {
namespace cpu {

namespace {

Expected<std::string, Error> readSysCpuFile(char const* path) {
  std::ifstream fin(path, std::ios_base::in | std::ios_base::binary);
  if (fin.fail() || fin.bad()) {
    return createError(Error::IOError)
           << "No access to the system file " << path;
  }
  auto data = std::string{};
  fin >> data;
  return data;
}

Expected<std::size_t, Error> decodeCpuNumber(const std::string& str) {
  auto exp = tryTo<std::size_t>(str);
  if (exp.isError()) {
    return createError(Error::IncorrectRange, exp.takeError())
           << "Incorrect CPU number representation " << boost::io::quoted(str);
  }
  return exp.take();
}

} // namespace

Expected<Mask, Error> decodeMaskFromString(const std::string& encoded_str) {
  auto mask = Mask{};
  if (encoded_str.empty()) {
    return mask;
  }
  using It = boost::split_iterator<std::string::const_iterator>;
  for (auto it = boost::make_split_iterator(
           encoded_str, boost::first_finder(",", boost::is_equal()));
       it != It{};
       ++it) {
    auto const interval = boost::copy_range<std::string>(*it);
    auto const dash_pos = interval.find("-");
    if (dash_pos == std::string::npos) {
      auto num_exp = decodeCpuNumber(interval);
      if (num_exp.isError()) {
        return num_exp.takeError();
      }
      if (num_exp.get() < mask.size()) {
        mask.set(num_exp.get());
      } else {
        return createError(Error::IncorrectRange)
               << "CPU number " << num_exp.get() << " out of bound [0,"
               << mask.size() << ")";
      }
    } else {
      auto from_exp = decodeCpuNumber(interval.substr(0, dash_pos));
      if (from_exp.isError()) {
        return from_exp.takeError();
      }
      auto to_exp = decodeCpuNumber(interval.substr(dash_pos + 1));
      if (to_exp.isError()) {
        return to_exp.takeError();
      }
      if (to_exp.get() < from_exp.get()) {
        return createError(Error::IncorrectRange)
               << "Incorrect CPU number interval "
               << boost::io::quoted(interval);
      }
      if (to_exp.get() >= mask.size()) {
        return createError(Error::IncorrectRange)
               << "CPU number " << to_exp.get() << " out of bound [0,"
               << mask.size() << ")";
      }
      for (auto pos = from_exp.get(); pos <= to_exp.get(); ++pos) {
        mask.set(pos);
      }
    }
  }
  return mask;
}

Expected<std::string, Error> getOfflineRaw() {
  return readSysCpuFile("/sys/devices/system/cpu/offline");
}

Expected<Mask, Error> getOffline() {
  auto exp = getOfflineRaw();
  if (exp.isError()) {
    return exp.takeError();
  }
  return decodeMaskFromString(exp.get());
}

Expected<std::string, Error> getOnlineRaw() {
  return readSysCpuFile("/sys/devices/system/cpu/online");
}

Expected<Mask, Error> getOnline() {
  auto exp = getOnlineRaw();
  if (exp.isError()) {
    return exp.takeError();
  }
  return decodeMaskFromString(exp.get());
}

Expected<std::string, Error> getPossibleRaw() {
  return readSysCpuFile("/sys/devices/system/cpu/possible");
}

Expected<Mask, Error> getPossible() {
  auto exp = getPossibleRaw();
  if (exp.isError()) {
    return exp.takeError();
  }
  return decodeMaskFromString(exp.get());
}

Expected<std::string, Error> getPresentRaw() {
  return readSysCpuFile("/sys/devices/system/cpu/present");
}

Expected<Mask, Error> getPresent() {
  auto exp = getPresentRaw();
  if (exp.isError()) {
    return exp.takeError();
  }
  return decodeMaskFromString(exp.get());
}

} // namespace cpu
} // namespace osquery

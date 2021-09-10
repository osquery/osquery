/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "pidfile.h"

namespace osquery {

struct Pidfile::PrivateData final {
  FileHandle file_handle;
  std::string path;
};

Expected<Pidfile, Pidfile::Error> Pidfile::create(
    const std::string& path) noexcept {
  try {
    return Pidfile(path);

  } catch (const std::bad_alloc&) {
    return createError(Error::MemoryAllocationFailure);

  } catch (const Error& error) {
    return createError(error);
  }
}

Pidfile::~Pidfile() {
  if (!d) {
    return;
  }

  closeFile(d->file_handle, d->path);
}

Pidfile::Pidfile(Pidfile&& other) noexcept {
  d = std::exchange(other.d, nullptr);
}

Pidfile& Pidfile::operator=(Pidfile&& other) noexcept {
  if (this != &other) {
    d = std::exchange(other.d, nullptr);
  }

  return *this;
}

Pidfile::Pidfile(const std::string& path) : d(new PrivateData) {
  auto file_handle_exp = createFile(path);
  if (file_handle_exp.isError()) {
    throw file_handle_exp.getErrorCode();
  }

  d->file_handle = file_handle_exp.take();
  d->path = path;
}

std::ostream& operator<<(std::ostream& stream, const Pidfile::Error& error) {
  switch (error) {
  case Pidfile::Error::Unknown:
    stream << "Pidfile::Error::Unknown";
    break;

  case Pidfile::Error::Busy:
    stream << "Pidfile::Error::Busy";
    break;

  case Pidfile::Error::AccessDenied:
    stream << "Pidfile::Error::AccessDenied";
    break;

  case Pidfile::Error::MemoryAllocationFailure:
    stream << "Pidfile::Error::MemoryAllocationFailure";
    break;

  case Pidfile::Error::IOError:
    stream << "Pidfile::Error::IOError";
    break;

  default:
    stream << "(Pidfile::Error) " << std::to_string(static_cast<int>(error));
    break;
  }

  return stream;
}

} // namespace osquery

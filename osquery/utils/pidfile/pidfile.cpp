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

Expected<std::uint64_t, Pidfile::Error> Pidfile::read(
    const std::string& path) noexcept {
  auto file_handle_exp = createFile(path);
  if (file_handle_exp.isError()) {
    return createError(file_handle_exp.getErrorCode());
  }

  auto file_handle = file_handle_exp.take();

  file_handle_exp = lockFile(file_handle);
  if (file_handle_exp.isValue()) {
    file_handle = file_handle_exp.take();
    destroyFile(file_handle, path);

    return createError(Error::NotRunning);
  }

  auto buffer_exp = readFile(file_handle);
  closeFile(file_handle);

  if (buffer_exp.isError()) {
    return createError(buffer_exp.getErrorCode());
  }

  auto buffer = buffer_exp.take();

  char* terminator{nullptr};
  auto process_id = std::strtoul(buffer.c_str(), &terminator, 10);
  if (process_id == 0 || terminator == nullptr || *terminator != 0) {
    return createError(Error::InvalidProcessID);
  }

  return process_id;
}

Pidfile::~Pidfile() {
  if (!d) {
    return;
  }

  destroyFile(d->file_handle, d->path);
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

  auto file_handle = file_handle_exp.take();

  file_handle_exp = lockFile(file_handle);
  if (file_handle_exp.isError()) {
    closeFile(file_handle);

    throw file_handle_exp.getErrorCode();
  }

  file_handle = file_handle_exp.take();

  auto opt_error = writeFile(file_handle);
  if (opt_error.has_value()) {
    destroyFile(file_handle, path);
    throw opt_error.value();
  }

  d->file_handle = file_handle;
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

  case Pidfile::Error::NotRunning:
    stream << "Pidfile::Error::NotRunning";
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

  case Pidfile::Error::InvalidProcessID:
    stream << "Pidfile::Error::InvalidProcessID";
    break;

  default:
    stream << "(Pidfile::Error) " << std::to_string(static_cast<int>(error));
    break;
  }

  return stream;
}

} // namespace osquery

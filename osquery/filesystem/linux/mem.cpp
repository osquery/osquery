/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <sys/mman.h>
#include <sys/types.h>

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include <osquery/core/flags.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>

namespace osquery {

#define kLinuxMaxMemRead 0x10000

const std::string kLinuxMemPath = "/dev/mem";

FLAG(bool, disable_memory, false, "Disable physical memory reads");

Status readMem(int fd, size_t base, size_t length, uint8_t* buffer) {
  if (lseek(fd, base, SEEK_SET) == -1) {
    return Status(1, "Cannot seek to physical base");
  }

  // Read from raw memory until an unrecoverable read error or the all of the
  // requested bytes are read.
  size_t total_read = 0;
  ssize_t bytes_read = -1;
  while (total_read != length && bytes_read != 0) {
    bytes_read = read(fd, buffer + total_read, length - total_read);
    if (bytes_read == -1) {
      if (errno != EINTR) {
        return Status(1, "Cannot read requested length");
      }
    } else {
      total_read += bytes_read;
    }
  }

  // The read call finished without reading the requested number of bytes.
  if (total_read != length) {
    return Status(1, "Read incorrect number of bytes");
  }

  return Status::success();
}

Status readRawMem(size_t base, size_t length, void** buffer) {
  *buffer = 0;

  if (FLAGS_disable_memory) {
    return Status(1, "Configuration has disabled physical memory reads");
  }

  if (length > kLinuxMaxMemRead) {
    return Status(1, "Cowardly refusing to read a large number of bytes");
  }

  auto status = isReadable(kLinuxMemPath);
  if (!status.ok()) {
    // For non-su users *hopefully* raw memory is not readable.
    return status;
  }

  int fd = open(kLinuxMemPath.c_str(), O_RDONLY);
  if (fd < 0) {
    return Status(1, std::string("Cannot open ") + kLinuxMemPath);
  }

  if ((*buffer = malloc(length)) == nullptr) {
    close(fd);
    return Status(1, "Cannot allocate memory for read");
  }

#ifdef _SC_PAGESIZE
  size_t offset = base % sysconf(_SC_PAGESIZE);
#else
  // getpagesize() is more or less deprecated.
  size_t offset = base % getpagesize();
#endif

  // Use memmap for maximum portability over read().
  auto map = mmap(0, offset + length, PROT_READ, MAP_SHARED, fd, base - offset);
  if (map == MAP_FAILED) {
    // Could fallback to a lseek/read.
    if (!readMem(fd, base, length, (uint8_t*)*buffer).ok()) {
      close(fd);
      free(*buffer);
      *buffer = nullptr;
      return Status(1, "Cannot memory map or seek/read memory");
    }
  } else {
    // Memory map succeeded, copy and unmap.
    memcpy(*buffer, (uint8_t*)map + offset, length);
    if (munmap(map, offset + length) == -1) {
      LOG(WARNING) << "Unable to unmap raw memory";
    }
  }

  close(fd);
  return Status::success();
}
}

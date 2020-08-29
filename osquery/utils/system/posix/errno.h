/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <errno.h>

#include <type_traits>

namespace osquery {

enum class PosixError {
  Unknown = 0,
  PERM = EPERM,
  NOENT = ENOENT,
  SRCH = ESRCH,
  INTR = EINTR,
  IO = EIO,
  NXIO = ENXIO,
  T_BIG = E2BIG,
  NOEXEC = ENOEXEC,
  BADF = EBADF,
  CHILD = ECHILD,
  AGAIN = EAGAIN,
  NOMEM = ENOMEM,
  ACCES = EACCES,
  FAULT = EFAULT,
  NOTBLK = ENOTBLK,
  BUSY = EBUSY,
  EXIST = EEXIST,
  XDEV = EXDEV,
  NODEV = ENODEV,
  NOTDIR = ENOTDIR,
  ISDIR = EISDIR,
  INVAL = EINVAL,
  NFILE = ENFILE,
  MFILE = EMFILE,
  NOTTY = ENOTTY,
  TXTBSY = ETXTBSY,
  FBIG = EFBIG,
  NOSPC = ENOSPC,
  SPIPE = ESPIPE,
  ROFS = EROFS,
  MLINK = EMLINK,
  PIPE = EPIPE,
  DOM = EDOM,
  RANGE = ERANGE,
};

namespace impl {

PosixError toPosixSystemError(int from_errno);

}

template <typename ToType>
inline typename std::enable_if<std::is_same<ToType, PosixError>::value,
                               PosixError>::type
to(int from_errno) {
  return impl::toPosixSystemError(from_errno);
}

} // namespace osquery

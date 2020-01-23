/**
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
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

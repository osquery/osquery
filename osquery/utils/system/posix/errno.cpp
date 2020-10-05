/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/utils/system/errno.h>
#include <osquery/utils/system/posix/errno.h>

#include <string.h>

#include <unordered_map>

namespace osquery {

std::string platformStrerr(int errnum) {
  return ::strerror(errnum);
}

namespace impl {

PosixError toPosixSystemError(int from_errno) {
  static auto const table = std::unordered_map<int, PosixError>{
      {EPERM, PosixError::PERM},     {ENOENT, PosixError::NOENT},
      {ESRCH, PosixError::SRCH},     {EINTR, PosixError::INTR},
      {EIO, PosixError::IO},         {ENXIO, PosixError::NXIO},
      {E2BIG, PosixError::T_BIG},    {ENOEXEC, PosixError::NOEXEC},
      {EBADF, PosixError::BADF},     {ECHILD, PosixError::CHILD},
      {EAGAIN, PosixError::AGAIN},   {ENOMEM, PosixError::NOMEM},
      {EACCES, PosixError::ACCES},   {EFAULT, PosixError::FAULT},
      {ENOTBLK, PosixError::NOTBLK}, {EBUSY, PosixError::BUSY},
      {EEXIST, PosixError::EXIST},   {EXDEV, PosixError::XDEV},
      {ENODEV, PosixError::NODEV},   {ENOTDIR, PosixError::NOTDIR},
      {EISDIR, PosixError::ISDIR},   {EINVAL, PosixError::INVAL},
      {ENFILE, PosixError::NFILE},   {EMFILE, PosixError::MFILE},
      {ENOTTY, PosixError::NOTTY},   {ETXTBSY, PosixError::TXTBSY},
      {EFBIG, PosixError::FBIG},     {ENOSPC, PosixError::NOSPC},
      {ESPIPE, PosixError::SPIPE},   {EROFS, PosixError::ROFS},
      {EMLINK, PosixError::MLINK},   {EPIPE, PosixError::PIPE},
      {EDOM, PosixError::DOM},       {ERANGE, PosixError::RANGE},
  };
  auto const it = table.find(from_errno);
  if (it == table.end()) {
    return PosixError::Unknown;
  }
  return it->second;
}

} // namespace impl

} // namespace osquery

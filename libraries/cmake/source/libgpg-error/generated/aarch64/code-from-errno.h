/* Output of mkerrcodes2.awk.  DO NOT EDIT.  */

/* errnos.h - List of system error values.
   Copyright (C) 2004 g10 Code GmbH
   This file is part of libgpg-error.

   libgpg-error is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License
   as published by the Free Software Foundation; either version 2.1 of
   the License, or (at your option) any later version.

   libgpg-error is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with libgpg-error; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
   02111-1307, USA.  */

static const int err_code_from_index[] = {
  GPG_ERR_EPERM,
  GPG_ERR_ENOENT,
  GPG_ERR_ESRCH,
  GPG_ERR_EINTR,
  GPG_ERR_EIO,
  GPG_ERR_ENXIO,
  GPG_ERR_E2BIG,
  GPG_ERR_ENOEXEC,
  GPG_ERR_EBADF,
  GPG_ERR_ECHILD,
  GPG_ERR_EAGAIN,
  GPG_ERR_EWOULDBLOCK,
  GPG_ERR_ENOMEM,
  GPG_ERR_EACCES,
  GPG_ERR_EFAULT,
  GPG_ERR_ENOTBLK,
  GPG_ERR_EBUSY,
  GPG_ERR_EEXIST,
  GPG_ERR_EXDEV,
  GPG_ERR_ENODEV,
  GPG_ERR_ENOTDIR,
  GPG_ERR_EISDIR,
  GPG_ERR_EINVAL,
  GPG_ERR_ENFILE,
  GPG_ERR_EMFILE,
  GPG_ERR_ENOTTY,
  GPG_ERR_ETXTBSY,
  GPG_ERR_EFBIG,
  GPG_ERR_ENOSPC,
  GPG_ERR_ESPIPE,
  GPG_ERR_EROFS,
  GPG_ERR_EMLINK,
  GPG_ERR_EPIPE,
  GPG_ERR_EDOM,
  GPG_ERR_ERANGE,
  GPG_ERR_EDEADLK,
  GPG_ERR_EDEADLOCK,
  GPG_ERR_ENAMETOOLONG,
  GPG_ERR_ENOLCK,
  GPG_ERR_ENOSYS,
  GPG_ERR_ENOTEMPTY,
  GPG_ERR_ELOOP,
  GPG_ERR_ENOMSG,
  GPG_ERR_EIDRM,
  GPG_ERR_ECHRNG,
  GPG_ERR_EL2NSYNC,
  GPG_ERR_EL3HLT,
  GPG_ERR_EL3RST,
  GPG_ERR_ELNRNG,
  GPG_ERR_EUNATCH,
  GPG_ERR_ENOCSI,
  GPG_ERR_EL2HLT,
  GPG_ERR_EBADE,
  GPG_ERR_EBADR,
  GPG_ERR_EXFULL,
  GPG_ERR_ENOANO,
  GPG_ERR_EBADRQC,
  GPG_ERR_EBADSLT,
  GPG_ERR_EBFONT,
  GPG_ERR_ENOSTR,
  GPG_ERR_ENODATA,
  GPG_ERR_ETIME,
  GPG_ERR_ENOSR,
  GPG_ERR_ENONET,
  GPG_ERR_ENOPKG,
  GPG_ERR_EREMOTE,
  GPG_ERR_ENOLINK,
  GPG_ERR_EADV,
  GPG_ERR_ESRMNT,
  GPG_ERR_ECOMM,
  GPG_ERR_EPROTO,
  GPG_ERR_EMULTIHOP,
  GPG_ERR_EDOTDOT,
  GPG_ERR_EBADMSG,
  GPG_ERR_EOVERFLOW,
  GPG_ERR_ENOTUNIQ,
  GPG_ERR_EBADFD,
  GPG_ERR_EREMCHG,
  GPG_ERR_ELIBACC,
  GPG_ERR_ELIBBAD,
  GPG_ERR_ELIBSCN,
  GPG_ERR_ELIBMAX,
  GPG_ERR_ELIBEXEC,
  GPG_ERR_EILSEQ,
  GPG_ERR_ERESTART,
  GPG_ERR_ESTRPIPE,
  GPG_ERR_EUSERS,
  GPG_ERR_ENOTSOCK,
  GPG_ERR_EDESTADDRREQ,
  GPG_ERR_EMSGSIZE,
  GPG_ERR_EPROTOTYPE,
  GPG_ERR_ENOPROTOOPT,
  GPG_ERR_EPROTONOSUPPORT,
  GPG_ERR_ESOCKTNOSUPPORT,
  GPG_ERR_ENOTSUP,
  GPG_ERR_EOPNOTSUPP,
  GPG_ERR_EPFNOSUPPORT,
  GPG_ERR_EAFNOSUPPORT,
  GPG_ERR_EADDRINUSE,
  GPG_ERR_EADDRNOTAVAIL,
  GPG_ERR_ENETDOWN,
  GPG_ERR_ENETUNREACH,
  GPG_ERR_ENETRESET,
  GPG_ERR_ECONNABORTED,
  GPG_ERR_ECONNRESET,
  GPG_ERR_ENOBUFS,
  GPG_ERR_EISCONN,
  GPG_ERR_ENOTCONN,
  GPG_ERR_ESHUTDOWN,
  GPG_ERR_ETOOMANYREFS,
  GPG_ERR_ETIMEDOUT,
  GPG_ERR_ECONNREFUSED,
  GPG_ERR_EHOSTDOWN,
  GPG_ERR_EHOSTUNREACH,
  GPG_ERR_EALREADY,
  GPG_ERR_EINPROGRESS,
  GPG_ERR_ESTALE,
  GPG_ERR_EUCLEAN,
  GPG_ERR_ENOTNAM,
  GPG_ERR_ENAVAIL,
  GPG_ERR_EISNAM,
  GPG_ERR_EREMOTEIO,
  GPG_ERR_EDQUOT,
  GPG_ERR_ENOMEDIUM,
  GPG_ERR_EMEDIUMTYPE,
  GPG_ERR_ECANCELED,
};

#define errno_to_idx(code) (0 ? -1 \
  : ((code >= 1) && (code <= 11)) ? (code - 1) \
  : ((code >= 11) && (code <= 35)) ? (code - 0) \
  : ((code >= 35) && (code <= 40)) ? (code - -1) \
  : ((code >= 42) && (code <= 57)) ? (code - 0) \
  : ((code >= 59) && (code <= 95)) ? (code - 1) \
  : ((code >= 95) && (code <= 125)) ? (code - 0) \
  : -1)

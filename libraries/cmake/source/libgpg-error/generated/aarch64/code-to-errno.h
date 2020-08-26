/* Output of mkerrnos.awk.  DO NOT EDIT.  */

/* errnos.in - List of system error values.
   Copyright (C) 2003, 2004 g10 Code GmbH

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



#include <errno.h>
#ifdef _WIN32
#include <winsock2.h>
#endif

static const int err_code_to_errno [] = {
#ifdef E2BIG
  E2BIG,
#else
#ifdef WSAE2BIG
  WSAE2BIG,
#else
  0,
#endif
#endif
#ifdef EACCES
  EACCES,
#else
#ifdef WSAEACCES
  WSAEACCES,
#else
  0,
#endif
#endif
#ifdef EADDRINUSE
  EADDRINUSE,
#else
#ifdef WSAEADDRINUSE
  WSAEADDRINUSE,
#else
  0,
#endif
#endif
#ifdef EADDRNOTAVAIL
  EADDRNOTAVAIL,
#else
#ifdef WSAEADDRNOTAVAIL
  WSAEADDRNOTAVAIL,
#else
  0,
#endif
#endif
#ifdef EADV
  EADV,
#else
#ifdef WSAEADV
  WSAEADV,
#else
  0,
#endif
#endif
#ifdef EAFNOSUPPORT
  EAFNOSUPPORT,
#else
#ifdef WSAEAFNOSUPPORT
  WSAEAFNOSUPPORT,
#else
  0,
#endif
#endif
#ifdef EAGAIN
  EAGAIN,
#else
#ifdef WSAEAGAIN
  WSAEAGAIN,
#else
  0,
#endif
#endif
#ifdef EALREADY
  EALREADY,
#else
#ifdef WSAEALREADY
  WSAEALREADY,
#else
  0,
#endif
#endif
#ifdef EAUTH
  EAUTH,
#else
#ifdef WSAEAUTH
  WSAEAUTH,
#else
  0,
#endif
#endif
#ifdef EBACKGROUND
  EBACKGROUND,
#else
#ifdef WSAEBACKGROUND
  WSAEBACKGROUND,
#else
  0,
#endif
#endif
#ifdef EBADE
  EBADE,
#else
#ifdef WSAEBADE
  WSAEBADE,
#else
  0,
#endif
#endif
#ifdef EBADF
  EBADF,
#else
#ifdef WSAEBADF
  WSAEBADF,
#else
  0,
#endif
#endif
#ifdef EBADFD
  EBADFD,
#else
#ifdef WSAEBADFD
  WSAEBADFD,
#else
  0,
#endif
#endif
#ifdef EBADMSG
  EBADMSG,
#else
#ifdef WSAEBADMSG
  WSAEBADMSG,
#else
  0,
#endif
#endif
#ifdef EBADR
  EBADR,
#else
#ifdef WSAEBADR
  WSAEBADR,
#else
  0,
#endif
#endif
#ifdef EBADRPC
  EBADRPC,
#else
#ifdef WSAEBADRPC
  WSAEBADRPC,
#else
  0,
#endif
#endif
#ifdef EBADRQC
  EBADRQC,
#else
#ifdef WSAEBADRQC
  WSAEBADRQC,
#else
  0,
#endif
#endif
#ifdef EBADSLT
  EBADSLT,
#else
#ifdef WSAEBADSLT
  WSAEBADSLT,
#else
  0,
#endif
#endif
#ifdef EBFONT
  EBFONT,
#else
#ifdef WSAEBFONT
  WSAEBFONT,
#else
  0,
#endif
#endif
#ifdef EBUSY
  EBUSY,
#else
#ifdef WSAEBUSY
  WSAEBUSY,
#else
  0,
#endif
#endif
#ifdef ECANCELED
  ECANCELED,
#else
#ifdef WSAECANCELED
  WSAECANCELED,
#else
  0,
#endif
#endif
#ifdef ECHILD
  ECHILD,
#else
#ifdef WSAECHILD
  WSAECHILD,
#else
  0,
#endif
#endif
#ifdef ECHRNG
  ECHRNG,
#else
#ifdef WSAECHRNG
  WSAECHRNG,
#else
  0,
#endif
#endif
#ifdef ECOMM
  ECOMM,
#else
#ifdef WSAECOMM
  WSAECOMM,
#else
  0,
#endif
#endif
#ifdef ECONNABORTED
  ECONNABORTED,
#else
#ifdef WSAECONNABORTED
  WSAECONNABORTED,
#else
  0,
#endif
#endif
#ifdef ECONNREFUSED
  ECONNREFUSED,
#else
#ifdef WSAECONNREFUSED
  WSAECONNREFUSED,
#else
  0,
#endif
#endif
#ifdef ECONNRESET
  ECONNRESET,
#else
#ifdef WSAECONNRESET
  WSAECONNRESET,
#else
  0,
#endif
#endif
#ifdef ED
  ED,
#else
#ifdef WSAED
  WSAED,
#else
  0,
#endif
#endif
#ifdef EDEADLK
  EDEADLK,
#else
#ifdef WSAEDEADLK
  WSAEDEADLK,
#else
  0,
#endif
#endif
#ifdef EDEADLOCK
  EDEADLOCK,
#else
#ifdef WSAEDEADLOCK
  WSAEDEADLOCK,
#else
  0,
#endif
#endif
#ifdef EDESTADDRREQ
  EDESTADDRREQ,
#else
#ifdef WSAEDESTADDRREQ
  WSAEDESTADDRREQ,
#else
  0,
#endif
#endif
#ifdef EDIED
  EDIED,
#else
#ifdef WSAEDIED
  WSAEDIED,
#else
  0,
#endif
#endif
#ifdef EDOM
  EDOM,
#else
#ifdef WSAEDOM
  WSAEDOM,
#else
  0,
#endif
#endif
#ifdef EDOTDOT
  EDOTDOT,
#else
#ifdef WSAEDOTDOT
  WSAEDOTDOT,
#else
  0,
#endif
#endif
#ifdef EDQUOT
  EDQUOT,
#else
#ifdef WSAEDQUOT
  WSAEDQUOT,
#else
  0,
#endif
#endif
#ifdef EEXIST
  EEXIST,
#else
#ifdef WSAEEXIST
  WSAEEXIST,
#else
  0,
#endif
#endif
#ifdef EFAULT
  EFAULT,
#else
#ifdef WSAEFAULT
  WSAEFAULT,
#else
  0,
#endif
#endif
#ifdef EFBIG
  EFBIG,
#else
#ifdef WSAEFBIG
  WSAEFBIG,
#else
  0,
#endif
#endif
#ifdef EFTYPE
  EFTYPE,
#else
#ifdef WSAEFTYPE
  WSAEFTYPE,
#else
  0,
#endif
#endif
#ifdef EGRATUITOUS
  EGRATUITOUS,
#else
#ifdef WSAEGRATUITOUS
  WSAEGRATUITOUS,
#else
  0,
#endif
#endif
#ifdef EGREGIOUS
  EGREGIOUS,
#else
#ifdef WSAEGREGIOUS
  WSAEGREGIOUS,
#else
  0,
#endif
#endif
#ifdef EHOSTDOWN
  EHOSTDOWN,
#else
#ifdef WSAEHOSTDOWN
  WSAEHOSTDOWN,
#else
  0,
#endif
#endif
#ifdef EHOSTUNREACH
  EHOSTUNREACH,
#else
#ifdef WSAEHOSTUNREACH
  WSAEHOSTUNREACH,
#else
  0,
#endif
#endif
#ifdef EIDRM
  EIDRM,
#else
#ifdef WSAEIDRM
  WSAEIDRM,
#else
  0,
#endif
#endif
#ifdef EIEIO
  EIEIO,
#else
#ifdef WSAEIEIO
  WSAEIEIO,
#else
  0,
#endif
#endif
#ifdef EILSEQ
  EILSEQ,
#else
#ifdef WSAEILSEQ
  WSAEILSEQ,
#else
  0,
#endif
#endif
#ifdef EINPROGRESS
  EINPROGRESS,
#else
#ifdef WSAEINPROGRESS
  WSAEINPROGRESS,
#else
  0,
#endif
#endif
#ifdef EINTR
  EINTR,
#else
#ifdef WSAEINTR
  WSAEINTR,
#else
  0,
#endif
#endif
#ifdef EINVAL
  EINVAL,
#else
#ifdef WSAEINVAL
  WSAEINVAL,
#else
  0,
#endif
#endif
#ifdef EIO
  EIO,
#else
#ifdef WSAEIO
  WSAEIO,
#else
  0,
#endif
#endif
#ifdef EISCONN
  EISCONN,
#else
#ifdef WSAEISCONN
  WSAEISCONN,
#else
  0,
#endif
#endif
#ifdef EISDIR
  EISDIR,
#else
#ifdef WSAEISDIR
  WSAEISDIR,
#else
  0,
#endif
#endif
#ifdef EISNAM
  EISNAM,
#else
#ifdef WSAEISNAM
  WSAEISNAM,
#else
  0,
#endif
#endif
#ifdef EL2HLT
  EL2HLT,
#else
#ifdef WSAEL2HLT
  WSAEL2HLT,
#else
  0,
#endif
#endif
#ifdef EL2NSYNC
  EL2NSYNC,
#else
#ifdef WSAEL2NSYNC
  WSAEL2NSYNC,
#else
  0,
#endif
#endif
#ifdef EL3HLT
  EL3HLT,
#else
#ifdef WSAEL3HLT
  WSAEL3HLT,
#else
  0,
#endif
#endif
#ifdef EL3RST
  EL3RST,
#else
#ifdef WSAEL3RST
  WSAEL3RST,
#else
  0,
#endif
#endif
#ifdef ELIBACC
  ELIBACC,
#else
#ifdef WSAELIBACC
  WSAELIBACC,
#else
  0,
#endif
#endif
#ifdef ELIBBAD
  ELIBBAD,
#else
#ifdef WSAELIBBAD
  WSAELIBBAD,
#else
  0,
#endif
#endif
#ifdef ELIBEXEC
  ELIBEXEC,
#else
#ifdef WSAELIBEXEC
  WSAELIBEXEC,
#else
  0,
#endif
#endif
#ifdef ELIBMAX
  ELIBMAX,
#else
#ifdef WSAELIBMAX
  WSAELIBMAX,
#else
  0,
#endif
#endif
#ifdef ELIBSCN
  ELIBSCN,
#else
#ifdef WSAELIBSCN
  WSAELIBSCN,
#else
  0,
#endif
#endif
#ifdef ELNRNG
  ELNRNG,
#else
#ifdef WSAELNRNG
  WSAELNRNG,
#else
  0,
#endif
#endif
#ifdef ELOOP
  ELOOP,
#else
#ifdef WSAELOOP
  WSAELOOP,
#else
  0,
#endif
#endif
#ifdef EMEDIUMTYPE
  EMEDIUMTYPE,
#else
#ifdef WSAEMEDIUMTYPE
  WSAEMEDIUMTYPE,
#else
  0,
#endif
#endif
#ifdef EMFILE
  EMFILE,
#else
#ifdef WSAEMFILE
  WSAEMFILE,
#else
  0,
#endif
#endif
#ifdef EMLINK
  EMLINK,
#else
#ifdef WSAEMLINK
  WSAEMLINK,
#else
  0,
#endif
#endif
#ifdef EMSGSIZE
  EMSGSIZE,
#else
#ifdef WSAEMSGSIZE
  WSAEMSGSIZE,
#else
  0,
#endif
#endif
#ifdef EMULTIHOP
  EMULTIHOP,
#else
#ifdef WSAEMULTIHOP
  WSAEMULTIHOP,
#else
  0,
#endif
#endif
#ifdef ENAMETOOLONG
  ENAMETOOLONG,
#else
#ifdef WSAENAMETOOLONG
  WSAENAMETOOLONG,
#else
  0,
#endif
#endif
#ifdef ENAVAIL
  ENAVAIL,
#else
#ifdef WSAENAVAIL
  WSAENAVAIL,
#else
  0,
#endif
#endif
#ifdef ENEEDAUTH
  ENEEDAUTH,
#else
#ifdef WSAENEEDAUTH
  WSAENEEDAUTH,
#else
  0,
#endif
#endif
#ifdef ENETDOWN
  ENETDOWN,
#else
#ifdef WSAENETDOWN
  WSAENETDOWN,
#else
  0,
#endif
#endif
#ifdef ENETRESET
  ENETRESET,
#else
#ifdef WSAENETRESET
  WSAENETRESET,
#else
  0,
#endif
#endif
#ifdef ENETUNREACH
  ENETUNREACH,
#else
#ifdef WSAENETUNREACH
  WSAENETUNREACH,
#else
  0,
#endif
#endif
#ifdef ENFILE
  ENFILE,
#else
#ifdef WSAENFILE
  WSAENFILE,
#else
  0,
#endif
#endif
#ifdef ENOANO
  ENOANO,
#else
#ifdef WSAENOANO
  WSAENOANO,
#else
  0,
#endif
#endif
#ifdef ENOBUFS
  ENOBUFS,
#else
#ifdef WSAENOBUFS
  WSAENOBUFS,
#else
  0,
#endif
#endif
#ifdef ENOCSI
  ENOCSI,
#else
#ifdef WSAENOCSI
  WSAENOCSI,
#else
  0,
#endif
#endif
#ifdef ENODATA
  ENODATA,
#else
#ifdef WSAENODATA
  WSAENODATA,
#else
  0,
#endif
#endif
#ifdef ENODEV
  ENODEV,
#else
#ifdef WSAENODEV
  WSAENODEV,
#else
  0,
#endif
#endif
#ifdef ENOENT
  ENOENT,
#else
#ifdef WSAENOENT
  WSAENOENT,
#else
  0,
#endif
#endif
#ifdef ENOEXEC
  ENOEXEC,
#else
#ifdef WSAENOEXEC
  WSAENOEXEC,
#else
  0,
#endif
#endif
#ifdef ENOLCK
  ENOLCK,
#else
#ifdef WSAENOLCK
  WSAENOLCK,
#else
  0,
#endif
#endif
#ifdef ENOLINK
  ENOLINK,
#else
#ifdef WSAENOLINK
  WSAENOLINK,
#else
  0,
#endif
#endif
#ifdef ENOMEDIUM
  ENOMEDIUM,
#else
#ifdef WSAENOMEDIUM
  WSAENOMEDIUM,
#else
  0,
#endif
#endif
#ifdef ENOMEM
  ENOMEM,
#else
#ifdef WSAENOMEM
  WSAENOMEM,
#else
  0,
#endif
#endif
#ifdef ENOMSG
  ENOMSG,
#else
#ifdef WSAENOMSG
  WSAENOMSG,
#else
  0,
#endif
#endif
#ifdef ENONET
  ENONET,
#else
#ifdef WSAENONET
  WSAENONET,
#else
  0,
#endif
#endif
#ifdef ENOPKG
  ENOPKG,
#else
#ifdef WSAENOPKG
  WSAENOPKG,
#else
  0,
#endif
#endif
#ifdef ENOPROTOOPT
  ENOPROTOOPT,
#else
#ifdef WSAENOPROTOOPT
  WSAENOPROTOOPT,
#else
  0,
#endif
#endif
#ifdef ENOSPC
  ENOSPC,
#else
#ifdef WSAENOSPC
  WSAENOSPC,
#else
  0,
#endif
#endif
#ifdef ENOSR
  ENOSR,
#else
#ifdef WSAENOSR
  WSAENOSR,
#else
  0,
#endif
#endif
#ifdef ENOSTR
  ENOSTR,
#else
#ifdef WSAENOSTR
  WSAENOSTR,
#else
  0,
#endif
#endif
#ifdef ENOSYS
  ENOSYS,
#else
#ifdef WSAENOSYS
  WSAENOSYS,
#else
  0,
#endif
#endif
#ifdef ENOTBLK
  ENOTBLK,
#else
#ifdef WSAENOTBLK
  WSAENOTBLK,
#else
  0,
#endif
#endif
#ifdef ENOTCONN
  ENOTCONN,
#else
#ifdef WSAENOTCONN
  WSAENOTCONN,
#else
  0,
#endif
#endif
#ifdef ENOTDIR
  ENOTDIR,
#else
#ifdef WSAENOTDIR
  WSAENOTDIR,
#else
  0,
#endif
#endif
#ifdef ENOTEMPTY
  ENOTEMPTY,
#else
#ifdef WSAENOTEMPTY
  WSAENOTEMPTY,
#else
  0,
#endif
#endif
#ifdef ENOTNAM
  ENOTNAM,
#else
#ifdef WSAENOTNAM
  WSAENOTNAM,
#else
  0,
#endif
#endif
#ifdef ENOTSOCK
  ENOTSOCK,
#else
#ifdef WSAENOTSOCK
  WSAENOTSOCK,
#else
  0,
#endif
#endif
#ifdef ENOTSUP
  ENOTSUP,
#else
#ifdef WSAENOTSUP
  WSAENOTSUP,
#else
  0,
#endif
#endif
#ifdef ENOTTY
  ENOTTY,
#else
#ifdef WSAENOTTY
  WSAENOTTY,
#else
  0,
#endif
#endif
#ifdef ENOTUNIQ
  ENOTUNIQ,
#else
#ifdef WSAENOTUNIQ
  WSAENOTUNIQ,
#else
  0,
#endif
#endif
#ifdef ENXIO
  ENXIO,
#else
#ifdef WSAENXIO
  WSAENXIO,
#else
  0,
#endif
#endif
#ifdef EOPNOTSUPP
  EOPNOTSUPP,
#else
#ifdef WSAEOPNOTSUPP
  WSAEOPNOTSUPP,
#else
  0,
#endif
#endif
#ifdef EOVERFLOW
  EOVERFLOW,
#else
#ifdef WSAEOVERFLOW
  WSAEOVERFLOW,
#else
  0,
#endif
#endif
#ifdef EPERM
  EPERM,
#else
#ifdef WSAEPERM
  WSAEPERM,
#else
  0,
#endif
#endif
#ifdef EPFNOSUPPORT
  EPFNOSUPPORT,
#else
#ifdef WSAEPFNOSUPPORT
  WSAEPFNOSUPPORT,
#else
  0,
#endif
#endif
#ifdef EPIPE
  EPIPE,
#else
#ifdef WSAEPIPE
  WSAEPIPE,
#else
  0,
#endif
#endif
#ifdef EPROCLIM
  EPROCLIM,
#else
#ifdef WSAEPROCLIM
  WSAEPROCLIM,
#else
  0,
#endif
#endif
#ifdef EPROCUNAVAIL
  EPROCUNAVAIL,
#else
#ifdef WSAEPROCUNAVAIL
  WSAEPROCUNAVAIL,
#else
  0,
#endif
#endif
#ifdef EPROGMISMATCH
  EPROGMISMATCH,
#else
#ifdef WSAEPROGMISMATCH
  WSAEPROGMISMATCH,
#else
  0,
#endif
#endif
#ifdef EPROGUNAVAIL
  EPROGUNAVAIL,
#else
#ifdef WSAEPROGUNAVAIL
  WSAEPROGUNAVAIL,
#else
  0,
#endif
#endif
#ifdef EPROTO
  EPROTO,
#else
#ifdef WSAEPROTO
  WSAEPROTO,
#else
  0,
#endif
#endif
#ifdef EPROTONOSUPPORT
  EPROTONOSUPPORT,
#else
#ifdef WSAEPROTONOSUPPORT
  WSAEPROTONOSUPPORT,
#else
  0,
#endif
#endif
#ifdef EPROTOTYPE
  EPROTOTYPE,
#else
#ifdef WSAEPROTOTYPE
  WSAEPROTOTYPE,
#else
  0,
#endif
#endif
#ifdef ERANGE
  ERANGE,
#else
#ifdef WSAERANGE
  WSAERANGE,
#else
  0,
#endif
#endif
#ifdef EREMCHG
  EREMCHG,
#else
#ifdef WSAEREMCHG
  WSAEREMCHG,
#else
  0,
#endif
#endif
#ifdef EREMOTE
  EREMOTE,
#else
#ifdef WSAEREMOTE
  WSAEREMOTE,
#else
  0,
#endif
#endif
#ifdef EREMOTEIO
  EREMOTEIO,
#else
#ifdef WSAEREMOTEIO
  WSAEREMOTEIO,
#else
  0,
#endif
#endif
#ifdef ERESTART
  ERESTART,
#else
#ifdef WSAERESTART
  WSAERESTART,
#else
  0,
#endif
#endif
#ifdef EROFS
  EROFS,
#else
#ifdef WSAEROFS
  WSAEROFS,
#else
  0,
#endif
#endif
#ifdef ERPCMISMATCH
  ERPCMISMATCH,
#else
#ifdef WSAERPCMISMATCH
  WSAERPCMISMATCH,
#else
  0,
#endif
#endif
#ifdef ESHUTDOWN
  ESHUTDOWN,
#else
#ifdef WSAESHUTDOWN
  WSAESHUTDOWN,
#else
  0,
#endif
#endif
#ifdef ESOCKTNOSUPPORT
  ESOCKTNOSUPPORT,
#else
#ifdef WSAESOCKTNOSUPPORT
  WSAESOCKTNOSUPPORT,
#else
  0,
#endif
#endif
#ifdef ESPIPE
  ESPIPE,
#else
#ifdef WSAESPIPE
  WSAESPIPE,
#else
  0,
#endif
#endif
#ifdef ESRCH
  ESRCH,
#else
#ifdef WSAESRCH
  WSAESRCH,
#else
  0,
#endif
#endif
#ifdef ESRMNT
  ESRMNT,
#else
#ifdef WSAESRMNT
  WSAESRMNT,
#else
  0,
#endif
#endif
#ifdef ESTALE
  ESTALE,
#else
#ifdef WSAESTALE
  WSAESTALE,
#else
  0,
#endif
#endif
#ifdef ESTRPIPE
  ESTRPIPE,
#else
#ifdef WSAESTRPIPE
  WSAESTRPIPE,
#else
  0,
#endif
#endif
#ifdef ETIME
  ETIME,
#else
#ifdef WSAETIME
  WSAETIME,
#else
  0,
#endif
#endif
#ifdef ETIMEDOUT
  ETIMEDOUT,
#else
#ifdef WSAETIMEDOUT
  WSAETIMEDOUT,
#else
  0,
#endif
#endif
#ifdef ETOOMANYREFS
  ETOOMANYREFS,
#else
#ifdef WSAETOOMANYREFS
  WSAETOOMANYREFS,
#else
  0,
#endif
#endif
#ifdef ETXTBSY
  ETXTBSY,
#else
#ifdef WSAETXTBSY
  WSAETXTBSY,
#else
  0,
#endif
#endif
#ifdef EUCLEAN
  EUCLEAN,
#else
#ifdef WSAEUCLEAN
  WSAEUCLEAN,
#else
  0,
#endif
#endif
#ifdef EUNATCH
  EUNATCH,
#else
#ifdef WSAEUNATCH
  WSAEUNATCH,
#else
  0,
#endif
#endif
#ifdef EUSERS
  EUSERS,
#else
#ifdef WSAEUSERS
  WSAEUSERS,
#else
  0,
#endif
#endif
#ifdef EWOULDBLOCK
  EWOULDBLOCK,
#else
#ifdef WSAEWOULDBLOCK
  WSAEWOULDBLOCK,
#else
  0,
#endif
#endif
#ifdef EXDEV
  EXDEV,
#else
#ifdef WSAEXDEV
  WSAEXDEV,
#else
  0,
#endif
#endif
#ifdef EXFULL
  EXFULL,
#else
#ifdef WSAEXFULL
  WSAEXFULL,
#else
  0,
#endif
#endif
};

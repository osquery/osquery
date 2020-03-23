/* Output of mkstrtable.awk.  DO NOT EDIT.  */

/* err-sources.h - List of error sources and their description.
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


/* The purpose of this complex string table is to produce
   optimal code with a minimum of relocations.  */

static const char msgstr[] = 
  "GPG_ERR_SOURCE_UNKNOWN" "\0"
  "GPG_ERR_SOURCE_GCRYPT" "\0"
  "GPG_ERR_SOURCE_GPG" "\0"
  "GPG_ERR_SOURCE_GPGSM" "\0"
  "GPG_ERR_SOURCE_GPGAGENT" "\0"
  "GPG_ERR_SOURCE_PINENTRY" "\0"
  "GPG_ERR_SOURCE_SCD" "\0"
  "GPG_ERR_SOURCE_GPGME" "\0"
  "GPG_ERR_SOURCE_KEYBOX" "\0"
  "GPG_ERR_SOURCE_KSBA" "\0"
  "GPG_ERR_SOURCE_DIRMNGR" "\0"
  "GPG_ERR_SOURCE_GSTI" "\0"
  "GPG_ERR_SOURCE_GPA" "\0"
  "GPG_ERR_SOURCE_KLEO" "\0"
  "GPG_ERR_SOURCE_G13" "\0"
  "GPG_ERR_SOURCE_ASSUAN" "\0"
  "GPG_ERR_SOURCE_TLS" "\0"
  "GPG_ERR_SOURCE_ANY" "\0"
  "GPG_ERR_SOURCE_USER_1" "\0"
  "GPG_ERR_SOURCE_USER_2" "\0"
  "GPG_ERR_SOURCE_USER_3" "\0"
  "GPG_ERR_SOURCE_USER_4" "\0"
  "GPG_ERR_SOURCE_DIM";

static const int msgidx[] =
  {
    0,
    23,
    45,
    64,
    85,
    109,
    133,
    152,
    173,
    195,
    215,
    238,
    258,
    277,
    297,
    316,
    338,
    357,
    376,
    398,
    420,
    442,
    464
  };

static GPG_ERR_INLINE int
msgidxof (int code)
{
  return (0 ? 0
  : ((code >= 0) && (code <= 15)) ? (code - 0)
  : ((code >= 17) && (code <= 17)) ? (code - 1)
  : ((code >= 31) && (code <= 35)) ? (code - 14)
  : 36 - 14);
}

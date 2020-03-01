/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#ifdef __x86_64__
#include <asm/unistd_64.h>
#else
#include <asm/unistd.h>
#endif

#include <set>



const std::set<int> kProcessFileEventsSyscalls = {
  __NR_linkat,
#ifndef __aarch64__
  __NR_symlink,
#endif
  __NR_symlinkat,
#ifndef __aarch64__
  __NR_unlink,
#endif
  __NR_unlinkat,
#ifndef __aarch64__
  __NR_rename,
#endif
  __NR_renameat,
  __NR_renameat2,
#ifndef __aarch64__
  __NR_creat,
  __NR_mknod,
 #endif
  __NR_mknodat,
 #ifndef __aarch64__
  __NR_open,
#endif
  __NR_openat,
  __NR_open_by_handle_at,
  __NR_name_to_handle_at,
  __NR_close,
  __NR_dup,
#ifndef __aarch64__
  __NR_dup2,
#endif
  __NR_dup3,
  __NR_pread64,
  __NR_preadv,
  __NR_read,
  __NR_readv,
  __NR_mmap,
  __NR_write,
  __NR_writev,
  __NR_pwrite64,
  __NR_pwritev,
  __NR_truncate,
  __NR_ftruncate,
  __NR_clone,
#ifndef __aarch64__
  __NR_fork,
  __NR_vfork
#endif
};

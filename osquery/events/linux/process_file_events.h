/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <asm/unistd.h>

#include <set>

const std::set<int> kProcessFileEventsSyscalls = {
    __NR_linkat,
    __NR_symlinkat,
    __NR_unlinkat,
    __NR_renameat,
    __NR_renameat2,
    __NR_mknodat,
    __NR_openat,
    __NR_open_by_handle_at,
    __NR_name_to_handle_at,
    __NR_close,
    __NR_dup,
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
/*
 * The following syscalls are deprecated on newer architectures
 */
#ifdef __x86_64__
    __NR_symlink,
    __NR_unlink,
    __NR_rename,
    __NR_creat,
    __NR_mknod,
    __NR_open,
    __NR_dup2,
    __NR_fork,
    __NR_vfork,
#endif /* __x86_64__ */
};

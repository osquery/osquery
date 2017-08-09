/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <gtest/gtest.h>

#include <linux/audit.h>

#include <cstdint>
#include <cstdio>
#include <ctime>
#include <string>
#include <vector>

#include <sstream>

#include <osquery/events.h>
#include <osquery/flags.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/events/linux/auditeventpublisher.h"
#include "osquery/tables/events/linux/auditd_fim_events.h"
#include "osquery/tests/test_util.h"
/*
const std::vector<std::pair<int, std::string>> complete_event_list = {
    {AUDIT_SYSCALL,
     "audit(1501323932.707:7670507): arch=c000003e syscall=3 success=yes "
     "exit=0 a0=3 a1=0 a2=f a3=7f20e4218a10 items=0 ppid=1236 pid=99999 "
     "auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 "
     "sgid=1000 fsgid=1000 tty=pts7 ses=34 comm=\"zsh\" exe=\"/usr/bin/zsh\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_EOE, "audit(1501323932.707:7670507): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.707:7670508): arch=c000003e syscall=3 success=yes "
     "exit=0 a0=4 a1=6b8f20 a2=96b020 a3=9 items=0 ppid=1236 pid=99999 "
     "auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 "
     "sgid=1000 fsgid=1000 tty=pts7 ses=34 comm=\"zsh\" exe=\"/usr/bin/zsh\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_EOE, "audit(1501323932.707:7670508): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.707:7670509): arch=c000003e syscall=0 success=yes "
     "exit=0 a0=3 a1=7ffe7b8aac28 a2=1 a3=7f20e4218a10 items=0 ppid=7812 "
     "pid=1236 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 "
     "egid=1000 sgid=1000 fsgid=1000 tty=pts7 ses=34 comm=\"zsh\" "
     "exe=\"/usr/bin/zsh\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_EOE, "audit(1501323932.707:7670509): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.707:7670511): arch=c000003e syscall=3 success=yes "
     "exit=0 a0=3 a1=7ffe7b8aac28 a2=1 a3=7f20e4218a10 items=0 ppid=7812 "
     "pid=1236 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 "
     "egid=1000 sgid=1000 fsgid=1000 tty=pts7 ses=34 comm=\"zsh\" "
     "exe=\"/usr/bin/zsh\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_EOE, "audit(1501323932.707:7670511): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.707:7670510): arch=c000003e syscall=3 success=yes "
     "exit=0 a0=a a1=0 a2=f a3=0 items=0 ppid=1236 pid=99999 auid=1000 "
     "uid=1000 "
     "gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 "
     "tty=pts7 ses=34 comm=\"zsh\" exe=\"/usr/bin/zsh\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_EOE, "audit(1501323932.707:7670510): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.707:7670512): arch=c000003e syscall=3 success=yes "
     "exit=0 a0=d a1=0 a2=f a3=0 items=0 ppid=1236 pid=99999 auid=1000 "
     "uid=1000 "
     "gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 "
     "tty=pts7 ses=34 comm=\"zsh\" exe=\"/usr/bin/zsh\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_EOE, "audit(1501323932.707:7670512): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.707:7670513): arch=c000003e syscall=3 success=yes "
     "exit=0 a0=e a1=0 a2=f a3=0 items=0 ppid=1236 pid=99999 auid=1000 "
     "uid=1000 "
     "gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 "
     "tty=pts7 ses=34 comm=\"zsh\" exe=\"/usr/bin/zsh\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_EOE, "audit(1501323932.707:7670513): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.708:7670514): arch=c000003e syscall=3 success=yes "
     "exit=0 a0=f a1=0 a2=96bc71 a3=0 items=0 ppid=1236 pid=99999 auid=1000 "
     "uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 "
     "fsgid=1000 tty=pts7 ses=34 comm=\"zsh\" exe=\"/usr/bin/zsh\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_EOE, "audit(1501323932.708:7670514): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.708:7670515): arch=c000003e syscall=3 success=no "
     "exit=-9 a0=f a1=ac7570 a2=ac7570 a3=0 items=0 ppid=1236 pid=99999 "
     "auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 "
     "sgid=1000 fsgid=1000 tty=pts7 ses=34 comm=\"zsh\" exe=\"/usr/bin/zsh\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_EOE, "audit(1501323932.708:7670515): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.708:7670516): arch=c000003e syscall=3 success=no "
     "exit=-9 a0=e a1=ac7570 a2=ac7570 a3=0 items=0 ppid=1236 pid=99999 "
     "auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 "
     "sgid=1000 fsgid=1000 tty=pts7 ses=34 comm=\"zsh\" exe=\"/usr/bin/zsh\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_EOE, "audit(1501323932.708:7670516): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.708:7670517): arch=c000003e syscall=3 success=no "
     "exit=-9 a0=d a1=ac7570 a2=ac7570 a3=0 items=0 ppid=1236 pid=99999 "
     "auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 "
     "sgid=1000 fsgid=1000 tty=pts7 ses=34 comm=\"zsh\" exe=\"/usr/bin/zsh\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_EOE, "audit(1501323932.708:7670517): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.708:7670518): arch=c000003e syscall=59 success=yes "
     "exit=0 a0=7f20e4119328 a1=7f20e4119340 a2=9c62d0 a3=7ffe7b8a15f0 items=2 "
     "ppid=1236 pid=99999 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 "
     "fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts7 ses=34 comm=\"test\" "
     "exe=\"/home/user/test\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_EXECVE, "audit(1501323932.708:7670518): argc=1 a0=\"./test\""},
    {AUDIT_CWD, "audit(1501323932.708:7670518):  cwd=\"/home/user\""},
    {AUDIT_PATH,
     "audit(1501323932.708:7670518): item=0 name=\"./test\" inode=1011065 "
     "dev=fd:02 mode=0100755 ouid=0 ogid=0 rdev=00:00 "
     "obj=unconfined_u:object_r:user_home_t:s0 objtype=NORMAL"},
    {AUDIT_PATH,
     "audit(1501323932.708:7670518): item=1 "
     "name=\"/lib64/ld-linux-x86-64.so.2\" inode=33555875 dev=fd:00 "
     "mode=0100755 ouid=0 ogid=0 rdev=00:00 obj=system_u:object_r:ld_so_t:s0 "
     "objtype=NORMAL"},
    {AUDIT_EOE, "audit(1501323932.708:7670518): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.708:7670519): arch=c000003e syscall=9 success=yes "
     "exit=139954710917120 a0=0 a1=1000 a2=3 a3=22 items=0 ppid=1236 pid=99999 "
     "auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 "
     "sgid=1000 fsgid=1000 tty=pts7 ses=34 comm=\"test\" "
     "exe=\"/home/user/test\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_EOE, "audit(1501323932.708:7670519): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.708:7670520): arch=c000003e syscall=2 success=yes "
     "exit=3 a0=7f49beb3fdf5 a1=80000 a2=1 a3=7f49bed464f8 items=1 ppid=1236 "
     "pid=99999 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 "
     "egid=1000 sgid=1000 fsgid=1000 tty=pts7 ses=34 comm=\"test\" "
     "exe=\"/home/user/test\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_CWD, "audit(1501323932.708:7670520):  cwd=\"/home/user\""},
    {AUDIT_PATH,
     "audit(1501323932.708:7670520): item=0 name=\"/etc/ld.so.cache\" "
     "inode=67183304 dev=fd:00 mode=0100644 ouid=0 ogid=0 rdev=00:00 "
     "obj=unconfined_u:object_r:ld_so_cache_t:s0 objtype=NORMAL"},
    {AUDIT_EOE, "audit(1501323932.708:7670520): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.708:7670521): arch=c000003e syscall=9 success=yes "
     "exit=139954710810624 a0=0 a1=19e73 a2=1 a3=2 items=0 ppid=1236 pid=99999 "
     "auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 "
     "sgid=1000 fsgid=1000 tty=pts7 ses=34 comm=\"test\" "
     "exe=\"/home/user/test\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_MMAP, "audit(1501323932.708:7670521): fd=3 flags=0x2"},
    {AUDIT_EOE, "audit(1501323932.708:7670521): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.708:7670522): arch=c000003e syscall=3 success=yes "
     "exit=0 a0=3 a1=19e73 a2=1 a3=2 items=0 ppid=1236 pid=99999 auid=1000 "
     "uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 "
     "fsgid=1000 tty=pts7 ses=34 comm=\"test\" exe=\"/home/user/test\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_EOE, "audit(1501323932.708:7670522): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.708:7670523): arch=c000003e syscall=2 success=yes "
     "exit=3 a0=7f49bed43640 a1=80000 a2=7f49bed46150 a3=7f49bed43640 items=1 "
     "ppid=1236 pid=99999 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 "
     "fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts7 ses=34 comm=\"test\" "
     "exe=\"/home/user/test\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_CWD, "audit(1501323932.708:7670523):  cwd=\"/home/user\""},
    {AUDIT_PATH,
     "audit(1501323932.708:7670523): item=0 name=\"/lib64/libc.so.6\" "
     "inode=33555889 dev=fd:00 mode=0100755 ouid=0 ogid=0 rdev=00:00 "
     "obj=system_u:object_r:lib_t:s0 objtype=NORMAL"},
    {AUDIT_EOE, "audit(1501323932.708:7670523): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.708:7670524): arch=c000003e syscall=0 success=yes "
     "exit=832 a0=3 a1=7ffcb2470470 a2=340 a3=7f49bed43640 items=0 ppid=1236 "
     "pid=99999 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 "
     "egid=1000 sgid=1000 fsgid=1000 tty=pts7 ses=34 comm=\"test\" "
     "exe=\"/home/user/test\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_EOE, "audit(1501323932.708:7670524): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.709:7670525): arch=c000003e syscall=9 success=yes "
     "exit=139954704756736 a0=0 a1=3c0200 a2=5 a3=802 items=0 ppid=1236 "
     "pid=99999 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 "
     "egid=1000 sgid=1000 fsgid=1000 tty=pts7 ses=34 comm=\"test\" "
     "exe=\"/home/user/test\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_MMAP, "audit(1501323932.709:7670525): fd=3 flags=0x802"},
    {AUDIT_EOE, "audit(1501323932.709:7670525): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.709:7670526): arch=c000003e syscall=9 success=yes "
     "exit=139954708647936 a0=7f49beb19000 a1=6000 a2=3 a3=812 items=0 "
     "ppid=1236 pid=99999 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 "
     "fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts7 ses=34 comm=\"test\" "
     "exe=\"/home/user/test\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_MMAP, "audit(1501323932.709:7670526): fd=3 flags=0x812"},
    {AUDIT_EOE, "audit(1501323932.709:7670526): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.709:7670527): arch=c000003e syscall=9 success=yes "
     "exit=139954708672512 a0=7f49beb1f000 a1=4200 a2=3 a3=32 items=0 "
     "ppid=1236 pid=99999 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 "
     "fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts7 ses=34 comm=\"test\" "
     "exe=\"/home/user/test\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_EOE, "audit(1501323932.709:7670527): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.709:7670528): arch=c000003e syscall=3 success=yes "
     "exit=0 a0=3 a1=7f49bed43698 a2=0 a3=31 items=0 ppid=1236 pid=99999 "
     "auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 "
     "sgid=1000 fsgid=1000 tty=pts7 ses=34 comm=\"test\" "
     "exe=\"/home/user/test\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_EOE, "audit(1501323932.709:7670528): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.709:7670529): arch=c000003e syscall=9 success=yes "
     "exit=139954710806528 a0=0 a1=1000 a2=3 a3=22 items=0 ppid=1236 pid=99999 "
     "auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 "
     "sgid=1000 fsgid=1000 tty=pts7 ses=34 comm=\"test\" "
     "exe=\"/home/user/test\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_EOE, "audit(1501323932.709:7670529): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.709:7670530): arch=c000003e syscall=9 success=yes "
     "exit=139954710798336 a0=0 a1=2000 a2=3 a3=22 items=0 ppid=1236 pid=99999 "
     "auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 "
     "sgid=1000 fsgid=1000 tty=pts7 ses=34 comm=\"test\" "
     "exe=\"/home/user/test\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_EOE, "audit(1501323932.709:7670530): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.709:7670531): arch=c000003e syscall=9 success=yes "
     "exit=139954710913024 a0=0 a1=1000 a2=3 a3=22 items=0 ppid=1236 pid=99999 "
     "auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 "
     "sgid=1000 fsgid=1000 tty=pts7 ses=34 comm=\"test\" "
     "exe=\"/home/user/test\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_EOE, "audit(1501323932.709:7670531): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.709:7670532): arch=c000003e syscall=1 success=yes "
     "exit=17 a0=1 a1=7f49bed42000 a2=11 a3=0 items=0 ppid=1236 pid=99999 "
     "auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 "
     "sgid=1000 fsgid=1000 tty=pts7 ses=34 comm=\"test\" "
     "exe=\"/home/user/test\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_EOE, "audit(1501323932.709:7670532): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.709:7670533): arch=c000003e syscall=1 per=400000 "
     "success=yes exit=8 a0=1a a1=7f34857b5ee8 a2=8 a3=0 items=0 ppid=12225 "
     "pid=12272 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 "
     "egid=1000 sgid=1000 fsgid=1000 tty=(none) ses=34 comm=\"code\" "
     "exe=\"/usr/share/code/code\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_EOE, "audit(1501323932.709:7670533): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.709:7670534): arch=c000003e syscall=0 per=400000 "
     "success=yes exit=8 a0=1a a1=7ffe732b04a0 a2=400 a3=10f7 items=0 "
     "ppid=12225 pid=12267 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 "
     "fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=(none) ses=34 "
     "comm=\"code\" exe=\"/usr/share/code/code\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_EOE, "audit(1501323932.709:7670534): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.709:7670535): arch=c000003e syscall=2 success=yes "
     "exit=3 a0=401181 a1=2 a2=7f49beb1fa00 a3=7ffcb2471410 items=1 ppid=1236 "
     "pid=99999 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 "
     "egid=1000 sgid=1000 fsgid=1000 tty=pts7 ses=34 comm=\"test\" "
     "exe=\"/home/user/test\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_CWD, "audit(1501323932.709:7670535):  cwd=\"/home/user\""},
    {AUDIT_PATH,
     "audit(1501323932.709:7670535): item=0 name=\"/home/user/test_file\" "
     "inode=1007599 dev=fd:02 mode=0100644 ouid=1000 ogid=1000 rdev=00:00 "
     "obj=unconfined_u:object_r:user_home_t:s0 objtype=NORMAL"},
    {AUDIT_EOE, "audit(1501323932.709:7670535): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.709:7670536): arch=c000003e syscall=0 success=yes "
     "exit=10 a0=3 a1=7ffcb2471730 a2=a a3=7ffcb2471410 items=0 ppid=1236 "
     "pid=99999 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 "
     "egid=1000 sgid=1000 fsgid=1000 tty=pts7 ses=34 comm=\"test\" "
     "exe=\"/home/user/test\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_EOE, "audit(1501323932.709:7670536): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.709:7670537): arch=c000003e syscall=1 success=yes "
     "exit=1024 a0=3 a1=7ffcb2471730 a2=400 a3=7ffcb2471410 items=0 ppid=1236 "
     "pid=99999 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 "
     "egid=1000 sgid=1000 fsgid=1000 tty=pts7 ses=34 comm=\"test\" "
     "exe=\"/home/user/test\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_EOE, "audit(1501323932.709:7670537): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.709:7670538): arch=c000003e syscall=32 success=yes "
     "exit=4 a0=3 a1=7ffcb2471730 a2=400 a3=7ffcb2471410 items=0 ppid=1236 "
     "pid=99999 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 "
     "egid=1000 sgid=1000 fsgid=1000 tty=pts7 ses=34 comm=\"test\" "
     "exe=\"/home/user/test\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_EOE, "audit(1501323932.709:7670538): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.709:7670539): arch=c000003e syscall=33 success=yes "
     "exit=10 a0=3 a1=a a2=400 a3=7ffcb2471410 items=0 ppid=1236 pid=99999 "
     "auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 "
     "sgid=1000 fsgid=1000 tty=pts7 ses=34 comm=\"test\" "
     "exe=\"/home/user/test\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_EOE, "audit(1501323932.709:7670539): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.709:7670540): arch=c000003e syscall=292 success=yes "
     "exit=11 a0=3 a1=b a2=0 a3=7ffcb2471410 items=0 ppid=1236 pid=99999 "
     "auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 "
     "sgid=1000 fsgid=1000 tty=pts7 ses=34 comm=\"test\" "
     "exe=\"/home/user/test\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_EOE, "audit(1501323932.709:7670540): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.709:7670541): arch=c000003e syscall=1 success=yes "
     "exit=41 a0=1 a1=7f49bed42000 a2=29 a3=5 items=0 ppid=1236 pid=99999 "
     "auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 "
     "sgid=1000 fsgid=1000 tty=pts7 ses=34 comm=\"test\" "
     "exe=\"/home/user/test\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_EOE, "audit(1501323932.709:7670541): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.710:7670542): arch=c000003e syscall=231 a0=1 a1=0 a2=1 "
     "a3=ffffffffffffff80 items=0 ppid=1236 pid=99999 auid=1000 uid=1000 "
     "gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 "
     "tty=pts7 ses=34 comm=\"test\" exe=\"/home/user/test\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_EOE, "audit(1501323932.710:7670542): "}};

const std::vector<std::pair<int, std::string>> broken_event_list = {
    {AUDIT_SYSCALL,
     "audit(1501323932.707:7670507): arch=c000003e syscall=3 success=yes "
     "exit=0 a0=3 a1=0 a2=f a3=7f20e4218a10 items=0 ppid=1236 pid=99999 "
     "auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 "
     "sgid=1000 fsgid=1000 tty=pts7 ses=34 comm=\"zsh\" exe=\"/usr/bin/zsh\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_EOE, "audit(1501323932.707:7670507): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.707:7670508): arch=c000003e syscall=3 success=yes "
     "exit=0 a0=4 a1=6b8f20 a2=96b020 a3=9 items=0 ppid=1236 pid=99999 "
     "auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 "
     "sgid=1000 fsgid=1000 tty=pts7 ses=34 comm=\"zsh\" exe=\"/usr/bin/zsh\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_EOE, "audit(1501323932.707:7670508): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.707:7670509): arch=c000003e syscall=0 success=yes "
     "exit=0 a0=3 a1=7ffe7b8aac28 a2=1 a3=7f20e4218a10 items=0 ppid=7812 "
     "pid=1236 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 "
     "egid=1000 sgid=1000 fsgid=1000 tty=pts7 ses=34 comm=\"zsh\" "
     "exe=\"/usr/bin/zsh\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_EOE, "audit(1501323932.707:7670509): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.707:7670511): arch=c000003e syscall=3 success=yes "
     "exit=0 a0=3 a1=7ffe7b8aac28 a2=1 a3=7f20e4218a10 items=0 ppid=7812 "
     "pid=1236 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 "
     "egid=1000 sgid=1000 fsgid=1000 tty=pts7 ses=34 comm=\"zsh\" "
     "exe=\"/usr/bin/zsh\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_EOE, "audit(1501323932.707:7670511): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.707:7670510): arch=c000003e syscall=3 success=yes "
     "exit=0 a0=a a1=0 a2=f a3=0 items=0 ppid=1236 pid=99999 auid=1000 "
     "uid=1000 "
     "gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 "
     "tty=pts7 ses=34 comm=\"zsh\" exe=\"/usr/bin/zsh\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_EOE, "audit(1501323932.707:7670510): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.707:7670512): arch=c000003e syscall=3 success=yes "
     "exit=0 a0=d a1=0 a2=f a3=0 items=0 ppid=1236 pid=99999 auid=1000 "
     "uid=1000 "
     "gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 "
     "tty=pts7 ses=34 comm=\"zsh\" exe=\"/usr/bin/zsh\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_EOE, "audit(1501323932.707:7670512): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.707:7670513): arch=c000003e syscall=3 success=yes "
     "exit=0 a0=e a1=0 a2=f a3=0 items=0 ppid=1236 pid=99999 auid=1000 "
     "uid=1000 "
     "gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 "
     "tty=pts7 ses=34 comm=\"zsh\" exe=\"/usr/bin/zsh\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_EOE, "audit(1501323932.707:7670513): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.708:7670514): arch=c000003e syscall=3 success=yes "
     "exit=0 a0=f a1=0 a2=96bc71 a3=0 items=0 ppid=1236 pid=99999 auid=1000 "
     "uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 "
     "fsgid=1000 tty=pts7 ses=34 comm=\"zsh\" exe=\"/usr/bin/zsh\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_EOE, "audit(1501323932.708:7670514): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.708:7670515): arch=c000003e syscall=3 success=no "
     "exit=-9 a0=f a1=ac7570 a2=ac7570 a3=0 items=0 ppid=1236 pid=99999 "
     "auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 "
     "sgid=1000 fsgid=1000 tty=pts7 ses=34 comm=\"zsh\" exe=\"/usr/bin/zsh\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_EOE, "audit(1501323932.708:7670515): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.708:7670516): arch=c000003e syscall=3 success=no "
     "exit=-9 a0=e a1=ac7570 a2=ac7570 a3=0 items=0 ppid=1236 pid=99999 "
     "auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 "
     "sgid=1000 fsgid=1000 tty=pts7 ses=34 comm=\"zsh\" exe=\"/usr/bin/zsh\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_EOE, "audit(1501323932.708:7670516): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.708:7670517): arch=c000003e syscall=3 success=no "
     "exit=-9 a0=d a1=ac7570 a2=ac7570 a3=0 items=0 ppid=1236 pid=99999 "
     "auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 "
     "sgid=1000 fsgid=1000 tty=pts7 ses=34 comm=\"zsh\" exe=\"/usr/bin/zsh\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_EOE, "audit(1501323932.708:7670517): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.708:7670518): arch=c000003e syscall=59 success=yes "
     "exit=0 a0=7f20e4119328 a1=7f20e4119340 a2=9c62d0 a3=7ffe7b8a15f0 items=2 "
     "ppid=1236 pid=99999 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 "
     "fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts7 ses=34 comm=\"test\" "
     "exe=\"/home/user/test\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_EXECVE, "audit(1501323932.708:7670518): argc=1 a0=\"./test\""},
    {AUDIT_CWD, "audit(1501323932.708:7670518):  cwd=\"/home/user\""},
    {AUDIT_PATH,
     "audit(1501323932.708:7670518): item=0 name=\"./test\" inode=1011065 "
     "dev=fd:02 mode=0100755 ouid=0 ogid=0 rdev=00:00 "
     "obj=unconfined_u:object_r:user_home_t:s0 objtype=NORMAL"},
    {AUDIT_PATH,
     "audit(1501323932.708:7670518): item=1 "
     "name=\"/lib64/ld-linux-x86-64.so.2\" inode=33555875 dev=fd:00 "
     "mode=0100755 ouid=0 ogid=0 rdev=00:00 obj=system_u:object_r:ld_so_t:s0 "
     "objtype=NORMAL"},
    {AUDIT_EOE, "audit(1501323932.708:7670518): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.708:7670519): arch=c000003e syscall=9 success=yes "
     "exit=139954710917120 a0=0 a1=1000 a2=3 a3=22 items=0 ppid=1236 pid=99999 "
     "auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 "
     "sgid=1000 fsgid=1000 tty=pts7 ses=34 comm=\"test\" "
     "exe=\"/home/user/test\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_SYSCALL,
     "audit(1501323932.708:7670520): arch=c000003e syscall=2 success=yes "
     "exit=3 a0=7f49beb3fdf5 a1=80000 a2=1 a3=7f49bed464f8 items=1 ppid=1236 "
     "pid=99999 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 "
     "egid=1000 sgid=1000 fsgid=1000 tty=pts7 ses=34 comm=\"test\" "
     "exe=\"/home/user/test\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_CWD, "audit(1501323932.708:7670520):  cwd=\"/home/user\""},
    {AUDIT_PATH,
     "audit(1501323932.708:7670520): item=0 name=\"/etc/ld.so.cache\" "
     "inode=67183304 dev=fd:00 mode=0100644 ouid=0 ogid=0 rdev=00:00 "
     "obj=unconfined_u:object_r:ld_so_cache_t:s0 objtype=NORMAL"},
    {AUDIT_EOE, "audit(1501323932.708:7670520): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.708:7670521): arch=c000003e syscall=9 success=yes "
     "exit=139954710810624 a0=0 a1=19e73 a2=1 a3=2 items=0 ppid=1236 pid=99999 "
     "auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 "
     "sgid=1000 fsgid=1000 tty=pts7 ses=34 comm=\"test\" "
     "exe=\"/home/user/test\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_MMAP, "audit(1501323932.708:7670521): fd=3 flags=0x2"},
    {AUDIT_SYSCALL,
     "audit(1501323932.708:7670522): arch=c000003e syscall=3 success=yes "
     "exit=0 a0=3 a1=19e73 a2=1 a3=2 items=0 ppid=1236 pid=99999 auid=1000 "
     "uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 "
     "fsgid=1000 tty=pts7 ses=34 comm=\"test\" exe=\"/home/user/test\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_EOE, "audit(1501323932.708:7670522): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.708:7670523): arch=c000003e syscall=2 success=yes "
     "exit=3 a0=7f49bed43640 a1=80000 a2=7f49bed46150 a3=7f49bed43640 items=1 "
     "ppid=1236 pid=99999 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 "
     "fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts7 ses=34 comm=\"test\" "
     "exe=\"/home/user/test\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_CWD, "audit(1501323932.708:7670523):  cwd=\"/home/user\""},
    {AUDIT_PATH,
     "audit(1501323932.708:7670523): item=0 name=\"/lib64/libc.so.6\" "
     "inode=33555889 dev=fd:00 mode=0100755 ouid=0 ogid=0 rdev=00:00 "
     "obj=system_u:object_r:lib_t:s0 objtype=NORMAL"},
    {AUDIT_SYSCALL,
     "audit(1501323932.708:7670524): arch=c000003e syscall=0 success=yes "
     "exit=832 a0=3 a1=7ffcb2470470 a2=340 a3=7f49bed43640 items=0 ppid=1236 "
     "pid=99999 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 "
     "egid=1000 sgid=1000 fsgid=1000 tty=pts7 ses=34 comm=\"test\" "
     "exe=\"/home/user/test\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_EOE, "audit(1501323932.708:7670524): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.709:7670525): arch=c000003e syscall=9 success=yes "
     "exit=139954704756736 a0=0 a1=3c0200 a2=5 a3=802 items=0 ppid=1236 "
     "pid=99999 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 "
     "egid=1000 sgid=1000 fsgid=1000 tty=pts7 ses=34 comm=\"test\" "
     "exe=\"/home/user/test\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_MMAP, "audit(1501323932.709:7670525): fd=3 flags=0x802"},
    {AUDIT_EOE, "audit(1501323932.709:7670525): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.709:7670526): arch=c000003e syscall=9 success=yes "
     "exit=139954708647936 a0=7f49beb19000 a1=6000 a2=3 a3=812 items=0 "
     "ppid=1236 pid=99999 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 "
     "fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts7 ses=34 comm=\"test\" "
     "exe=\"/home/user/test\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_MMAP, "audit(1501323932.709:7670526): fd=3 flags=0x812"},
    {AUDIT_EOE, "audit(1501323932.709:7670526): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.709:7670527): arch=c000003e syscall=9 success=yes "
     "exit=139954708672512 a0=7f49beb1f000 a1=4200 a2=3 a3=32 items=0 "
     "ppid=1236 pid=99999 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 "
     "fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts7 ses=34 comm=\"test\" "
     "exe=\"/home/user/test\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_EOE, "audit(1501323932.709:7670527): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.709:7670528): arch=c000003e syscall=3 success=yes "
     "exit=0 a0=3 a1=7f49bed43698 a2=0 a3=31 items=0 ppid=1236 pid=99999 "
     "auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 "
     "sgid=1000 fsgid=1000 tty=pts7 ses=34 comm=\"test\" "
     "exe=\"/home/user/test\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_EOE, "audit(1501323932.709:7670528): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.709:7670529): arch=c000003e syscall=9 success=yes "
     "exit=139954710806528 a0=0 a1=1000 a2=3 a3=22 items=0 ppid=1236 pid=99999 "
     "auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 "
     "sgid=1000 fsgid=1000 tty=pts7 ses=34 comm=\"test\" "
     "exe=\"/home/user/test\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_EOE, "audit(1501323932.709:7670529): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.709:7670530): arch=c000003e syscall=9 success=yes "
     "exit=139954710798336 a0=0 a1=2000 a2=3 a3=22 items=0 ppid=1236 pid=99999 "
     "auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 "
     "sgid=1000 fsgid=1000 tty=pts7 ses=34 comm=\"test\" "
     "exe=\"/home/user/test\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_EOE, "audit(1501323932.709:7670530): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.709:7670531): arch=c000003e syscall=9 success=yes "
     "exit=139954710913024 a0=0 a1=1000 a2=3 a3=22 items=0 ppid=1236 pid=99999 "
     "auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 "
     "sgid=1000 fsgid=1000 tty=pts7 ses=34 comm=\"test\" "
     "exe=\"/home/user/test\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_EOE, "audit(1501323932.709:7670531): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.709:7670532): arch=c000003e syscall=1 success=yes "
     "exit=17 a0=1 a1=7f49bed42000 a2=11 a3=0 items=0 ppid=1236 pid=99999 "
     "auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 "
     "sgid=1000 fsgid=1000 tty=pts7 ses=34 comm=\"test\" "
     "exe=\"/home/user/test\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_EOE, "audit(1501323932.709:7670532): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.709:7670533): arch=c000003e syscall=1 per=400000 "
     "success=yes exit=8 a0=1a a1=7f34857b5ee8 a2=8 a3=0 items=0 ppid=12225 "
     "pid=12272 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 "
     "egid=1000 sgid=1000 fsgid=1000 tty=(none) ses=34 comm=\"code\" "
     "exe=\"/usr/share/code/code\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_EOE, "audit(1501323932.709:7670533): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.709:7670534): arch=c000003e syscall=0 per=400000 "
     "success=yes exit=8 a0=1a a1=7ffe732b04a0 a2=400 a3=10f7 items=0 "
     "ppid=12225 pid=12267 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 "
     "fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=(none) ses=34 "
     "comm=\"code\" exe=\"/usr/share/code/code\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_EOE, "audit(1501323932.709:7670534): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.709:7670535): arch=c000003e syscall=2 success=yes "
     "exit=3 a0=401181 a1=2 a2=7f49beb1fa00 a3=7ffcb2471410 items=1 ppid=1236 "
     "pid=99999 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 "
     "egid=1000 sgid=1000 fsgid=1000 tty=pts7 ses=34 comm=\"test\" "
     "exe=\"/home/user/test\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_CWD, "audit(1501323932.709:7670535):  cwd=\"/home/user\""},
    {AUDIT_PATH,
     "audit(1501323932.709:7670535): item=0 name=\"/home/user/test_file\" "
     "inode=1007599 dev=fd:02 mode=0100644 ouid=1000 ogid=1000 rdev=00:00 "
     "obj=unconfined_u:object_r:user_home_t:s0 objtype=NORMAL"},
    {AUDIT_EOE, "audit(1501323932.709:7670535): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.709:7670536): arch=c000003e syscall=0 success=yes "
     "exit=10 a0=3 a1=7ffcb2471730 a2=a a3=7ffcb2471410 items=0 ppid=1236 "
     "pid=99999 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 "
     "egid=1000 sgid=1000 fsgid=1000 tty=pts7 ses=34 comm=\"test\" "
     "exe=\"/home/user/test\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_EOE, "audit(1501323932.709:7670536): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.709:7670537): arch=c000003e syscall=1 success=yes "
     "exit=1024 a0=3 a1=7ffcb2471730 a2=400 a3=7ffcb2471410 items=0 ppid=1236 "
     "pid=99999 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 "
     "egid=1000 sgid=1000 fsgid=1000 tty=pts7 ses=34 comm=\"test\" "
     "exe=\"/home/user/test\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_EOE, "audit(1501323932.709:7670537): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.709:7670538): arch=c000003e syscall=32 success=yes "
     "exit=4 a0=3 a1=7ffcb2471730 a2=400 a3=7ffcb2471410 items=0 ppid=1236 "
     "pid=99999 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 "
     "egid=1000 sgid=1000 fsgid=1000 tty=pts7 ses=34 comm=\"test\" "
     "exe=\"/home/user/test\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_EOE, "audit(1501323932.709:7670538): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.709:7670539): arch=c000003e syscall=33 success=yes "
     "exit=10 a0=3 a1=a a2=400 a3=7ffcb2471410 items=0 ppid=1236 pid=99999 "
     "auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 "
     "sgid=1000 fsgid=1000 tty=pts7 ses=34 comm=\"test\" "
     "exe=\"/home/user/test\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_EOE, "audit(1501323932.709:7670539): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.709:7670540): arch=c000003e syscall=292 success=yes "
     "exit=11 a0=3 a1=b a2=0 a3=7ffcb2471410 items=0 ppid=1236 pid=99999 "
     "auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 "
     "sgid=1000 fsgid=1000 tty=pts7 ses=34 comm=\"test\" "
     "exe=\"/home/user/test\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_EOE, "audit(1501323932.709:7670540): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.709:7670541): arch=c000003e syscall=1 success=yes "
     "exit=41 a0=1 a1=7f49bed42000 a2=29 a3=5 items=0 ppid=1236 pid=99999 "
     "auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 "
     "sgid=1000 fsgid=1000 tty=pts7 ses=34 comm=\"test\" "
     "exe=\"/home/user/test\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_EOE, "audit(1501323932.709:7670541): "},
    {AUDIT_SYSCALL,
     "audit(1501323932.710:7670542): arch=c000003e syscall=231 a0=1 a1=0 a2=1 "
     "a3=ffffffffffffff80 items=0 ppid=1236 pid=99999 auid=1000 uid=1000 "
     "gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 "
     "tty=pts7 ses=34 comm=\"test\" exe=\"/home/user/test\" "
     "subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
    {AUDIT_EOE, "audit(1501323932.710:7670542): "}};

namespace osquery {
extern std::string generateAuditId(std::uint32_t event_id) noexcept;

class AuditdFimTests : public testing::Test {
 protected:
  void SetUp() override {
    Row().swap(row_);
  }

 protected:
  Row row_;
};

TEST_F(AuditdFimTests, correct_record_sequence) {
  std::vector<AuditEventRecord> event_record_list;

  for (const auto& record_descriptor : complete_event_list) {
    std::string audit_message_copy = record_descriptor.second;

    audit_reply reply = {};
    reply.type = record_descriptor.first;
    reply.len = audit_message_copy.size();
    reply.message = &audit_message_copy[0];

    AuditEventRecord audit_event_record = {};

    bool parser_status =
        AuditdNetlink::ParseAuditReply(reply, audit_event_record);
    EXPECT_EQ(parser_status, true);

    event_record_list.push_back(audit_event_record);
  }

  EXPECT_EQ(event_record_list.size(), 85U);

  auto event_context = std::make_shared<AuditEventContext>();
  AuditTraceContext syscall_trace_context;

  AuditEventPublisher::ProcessEvents(
      event_context, event_record_list, syscall_trace_context);

  EXPECT_EQ(syscall_trace_context.size(), 0U);
  EXPECT_EQ(event_context->audit_events.size(), 36U);
}

TEST_F(AuditdFimTests, broken_record_sequence) {
  std::vector<AuditEventRecord> event_record_list;

  for (const auto& record_descriptor : broken_event_list) {
    std::string audit_message_copy = record_descriptor.second;

    audit_reply reply = {};
    reply.type = record_descriptor.first;
    reply.len = audit_message_copy.size();
    reply.message = &audit_message_copy[0];

    AuditEventRecord audit_event_record = {};

    // The pre-recorded event list contains timestamps from the past; these are
    // older than the 5 minutes limit used by ParseAuditReply to drop broken
    // events. In short, the cleanup procedure will delete those incomplete
    // records right away

    bool parser_status =
        AuditdNetlink::ParseAuditReply(reply, audit_event_record);
    EXPECT_EQ(parser_status, true);

    event_record_list.push_back(audit_event_record);
  }

  EXPECT_EQ(event_record_list.size(), 82U);

  auto event_context = std::make_shared<AuditEventContext>();
  AuditTraceContext syscall_trace_context;

  AuditEventPublisher::ProcessEvents(
      event_context, event_record_list, syscall_trace_context);

  EXPECT_EQ(syscall_trace_context.size(), 0U);
  EXPECT_EQ(event_context->audit_events.size(), 33U);
}

TEST_F(AuditdFimTests, row_emission) {
  std::vector<AuditEventRecord> event_record_list;

  for (const auto& record_descriptor : complete_event_list) {
    std::string audit_message_copy = record_descriptor.second;

    audit_reply reply = {};
    reply.type = record_descriptor.first;
    reply.len = audit_message_copy.size();
    reply.message = &audit_message_copy[0];

    AuditEventRecord audit_event_record = {};

    bool parser_status =
        AuditdNetlink::ParseAuditReply(reply, audit_event_record);
    EXPECT_EQ(parser_status, true);

    event_record_list.push_back(audit_event_record);
  }

  EXPECT_EQ(event_record_list.size(), 85U);

  auto event_context = std::make_shared<AuditEventContext>();
  AuditTraceContext syscall_trace_context;

  AuditEventPublisher::ProcessEvents(
      event_context, event_record_list, syscall_trace_context);

  EXPECT_EQ(syscall_trace_context.size(), 0U);
  EXPECT_EQ(event_context->audit_events.size(), 36U);

  // First test, showing only write operations. We expect to find a single write
  // here.
  AuditdFimConfiguration configuration;
  configuration.show_accesses = false;
  configuration.included_path_list.push_back("/home/user/test_file");

  AuditdFimProcessMap process_map;
  std::vector<Row> emitted_row_list;

  auto exit_status =
      AuditdFimEventSubscriber::ProcessEvents(emitted_row_list,
                                              process_map,
                                              configuration,
                                              event_context->audit_events);
  EXPECT_EQ(exit_status.ok(), true);
  EXPECT_EQ(emitted_row_list.size(), 1U);

  // Second test, with access events enabled
  configuration.show_accesses = true;

  configuration.included_path_list.clear();
  configuration.included_path_list.push_back("/etc/ld.so.cache");
  configuration.included_path_list.push_back("/home/user/test_file");
  configuration.included_path_list.push_back("/lib64/libc.so.6");

  configuration.excluded_path_list.push_back("/home/user/test_file");

  process_map.clear();
  emitted_row_list.clear();

  exit_status =
      AuditdFimEventSubscriber::ProcessEvents(emitted_row_list,
                                              process_map,
                                              configuration,
                                              event_context->audit_events);
  EXPECT_EQ(exit_status.ok(), true);
  EXPECT_EQ(emitted_row_list.size(), 7U);
}
}
*/
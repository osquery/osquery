/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <functional>
#include <unistd.h>

#include <osquery/status.h>

#if __GLIBC__ == 2 && __GLIBC_MINOR__ < 14
#include "syscall.h"
#if !defined(SYS_setns) && defined(__NR_setns)
#define SYS_setns __NR_setns
#endif
#ifndef SYS_setns
#error "setns(2) syscall not supported by glibc version"
#endif

static inline int setns(int fd, int nstype) {
  return syscall(SYS_setns, fd, nstype);
}
#endif

namespace osquery {
namespace tables {

/**
 * @brief NamespaceOps provides an interface to run a function in another
 * namespace and stream the results back to the parent process
 */
class NamespaceOps {
 public:
  NamespaceOps(int pid, int sockFD) : _pid{pid}, _sockFD{sockFD} {}

  /**
   * @brief invokes the specified function in the namespace
   */
  Status invoke(std::function<void(int fd)> fn);

  /**
   * @brief blocks the caller until the operations in the namespace has been
   * completed
   */
  void wait();

  ~NamespaceOps() {}

 private:
  pid_t _childPid;
  int _pid;
  int _sockFD;
};
}
}

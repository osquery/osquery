/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <osquery/logger.h>
#include <osquery/tables/applications/linux/namespace_ops.h>

namespace osquery {
namespace tables {

Status NamespaceOps::invoke(std::function<void(int fd)> fn) {
  std::string pidns = "/proc/" + std::to_string(_pid) + "/ns/mnt";
  int fd = open(pidns.c_str(), O_RDONLY);
  if (fd == -1) {
    VLOG(1) << "unable to open mnt ns for pid " << _pid << " : "
            << strerror(errno);
    return Status(1, strerror(errno));
  }

  pid_t childPid = fork();
  if (childPid == -1) {
    return Status(1, strerror(errno));
  }
  if (childPid != 0) {
    _childPid = childPid;
    close(fd);
    return Status();
  }

  // Change the namespace
  if (setns(fd, 0) == -1) {
    close(fd);
    close(_sockFD);
    _Exit(EXIT_SUCCESS);
  }

  // Execute the function
  fn(_sockFD);

  // Close the file handles and exit
  close(fd);
  close(_sockFD);
  _Exit(EXIT_SUCCESS);
}

void NamespaceOps::wait() {
  int wstatus;
  if (waitpid(_childPid, &wstatus, WUNTRACED | WCONTINUED) == -1) {
    VLOG(1) << "unable to wait for child pid";
    return;
  }
}
}
}

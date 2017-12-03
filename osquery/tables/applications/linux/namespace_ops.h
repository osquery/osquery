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

class NamespaceOps {
 public:
  NamespaceOps(int pid, int sockFD) : _pid{pid}, _sockFD{sockFD} {}

  Status invoke(std::function<void(int fd)> fn);

  void wait();

  ~NamespaceOps() {}

 private:
  pid_t _childPid;
  int _pid;
  int _sockFD;
};
}
}

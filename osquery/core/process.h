/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <string>
#include <boost/optional.hpp>

#include <osquery/core.h>

namespace osquery {

#ifdef WIN32
using PlatformPidType = HANDLE;
#else
using PlatformPidType = pid_t;
#endif

const PlatformPidType kInvalidPid = (PlatformPidType) -1;

class PlatformProcess {
  public:
    PlatformProcess(PlatformPidType id);
    PlatformProcess(PlatformProcess&& src);
    ~PlatformProcess();

    PlatformPidType nativeHandle() { return id_; }
    
    // TODO(#1991): Consider making kill() return an enumeration for more granularity if an
    //              error happens to occur.
    // TODO(#1991): Also, consider adding an argument for exit code so that clients can specificy
    //               the process exit code for the terminating process.
    bool kill();
    
    bool isValid() { return (id_ != kInvalidPid); }

    // TODO(#1991): Before we can start substituting code blocks with our abstractions, we need to
    //              decide on what to do for assignment operators. Integration requires some fields
    //              in classes to be retyped as PlatformProcess. On the Windows side, we need to 
    //              actually deal with resources such as HANDLEs. To prevent the leaking or premature
    //              closing of HANDLEs, we need to decide upon the semantics.
    //        
    //              Ideally, I think the way to go about it is on assignment, copy to the new object
    //              via duplication. This makes things decidably easier since after the operation,
    //              both HANDLEs are usable.

    // bool operator=(const PlatformProcess&& process);
    // bool operator==(const PlatformProcess& process);
    // bool operator!=(const PlatformProcess& process);
    
    static PlatformProcess launchWorker(const std::string& exec_path, const std::string& name);
    static PlatformProcess launchExtension(const std::string& exec_path, 
                                           const std::string& extension,
                                           const std::string& extensions_socket,
                                           const std::string& extensions_timeout,
                                           const std::string& extensions_interval,
                                           const std::string& verbose);
    static PlatformProcess fromPlatformPid(PlatformPidType id);
    
  private:
    PlatformPidType id_ = kInvalidPid;
};

PlatformProcess getCurrentProcess();
PlatformProcess getLauncherProcess();

void processSleep(unsigned int msec);

bool isLauncherProcessDead(PlatformProcess& launcher);
bool setEnvVar(const std::string& name, const std::string& value);
bool unsetEnvVar(const std::string& name);
boost::optional<std::string> getEnvVar(const std::string& name);

// TODO(#1991): Missing register signal handlers function. Consider using an abstraction layer for 
//              conforming POSIX and Windows callback functions. We should consider using a lambda
//              function for a more cleaner design.
// void registerExitHandlers(<func-ptr-type>);

// TODO(#1991): Missing waitpid functionality
// bool checkChildProcessStatus(osquery::PlatformProcess& process, int& status); -- watcher.cpp:193
// void cleanupDefunctProcesses(); -- watcher.cpp:227
}

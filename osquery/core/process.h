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

enum ProcessState {
  PROCESS_ERROR           = -1,
  PROCESS_STILL_ALIVE     =  0,
  PROCESS_EXITED,
  PROCESS_STATE_CHANGE
};

class PlatformProcess {
  public:
    PlatformProcess(): id_(kInvalidPid) { }
    PlatformProcess(PlatformPidType id);
    PlatformProcess(const PlatformProcess& src);
    PlatformProcess(PlatformProcess&& src);
    ~PlatformProcess();

    int pid() const;

    PlatformPidType nativeHandle() const { return id_; }
    
    // TODO(#1991): Consider making kill() return an enumeration for more granularity if an
    //              error happens to occur.
    // TODO(#1991): Also, consider adding an argument for exit code so that clients can specificy
    //               the process exit code for the terminating process.
    bool kill() const;
    
    bool isValid() const { return (id_ != kInvalidPid); }

    PlatformProcess& operator=(const PlatformProcess& process);
    bool operator==(const PlatformProcess& process) const;
    bool operator!=(const PlatformProcess& process) const;
    
    static PlatformProcess launchWorker(const std::string& exec_path, const std::string& name);
    static PlatformProcess launchExtension(const std::string& exec_path, 
                                           const std::string& extension,
                                           const std::string& extensions_socket,
                                           const std::string& extensions_timeout,
                                           const std::string& extensions_interval,
                                           const std::string& verbose);
    static PlatformProcess fromPlatformPid(PlatformPidType id);
    
  private:
    PlatformPidType id_{ kInvalidPid };
};

PlatformProcess getCurrentProcess();
PlatformProcess getLauncherProcess();

void processSleep(unsigned int msec);

bool setEnvVar(const std::string& name, const std::string& value);
bool unsetEnvVar(const std::string& name);
boost::optional<std::string> getEnvVar(const std::string& name);

bool isLauncherProcessDead(PlatformProcess& launcher);
ProcessState checkChildProcessStatus(const osquery::PlatformProcess& process, int& status);
void cleanupDefunctProcesses();

void setToBackgroundPriority();

// TODO(#1991): Missing register signal handlers function. Consider using an abstraction layer for 
//              conforming POSIX and Windows callback functions. We should consider using a lambda
//              function for a more cleaner design.
// void registerExitHandlers(<func-ptr-type>); -- init.cpp:306

// TODO(#1991): System logging?
}

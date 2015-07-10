/*
 *  Copyright (c) 2015, Google, Inc.
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

// User client class for user mode-I/O Kit kernel driver communication.
// Additional information about the user client class can be found here:
// http://goo.gl/vha0Wq

#include <IOKit/IOUserClient.h>

#include "kernel/darwin/iokit/driver.h"

#define OsqueryUserClientClassName com_facebook_iokit_osqueryUserClient

class OsqueryUserClientClassName : public IOUserClient {
  OSDeclareDefaultStructors(com_facebook_iokit_osqueryUserClient);

 public:
  // Initializes user client when the user process calls IOServiceOpen.
  bool initWithTask(task_t owningTask, void *securityID, UInt32 type) override;
  // Stores pointer to provider. Called after initWithTask as a result of the
  // user process calling IOServiceOpen.
  bool start(IOService *provider) override;
  // Closes provider. Called when user process calls IOServiceClose() or client
  // user process terminates unexpectedly.
  IOReturn clientClose() override;
  // Closes provider. Called at the end of the user client termination process.
  bool didTerminate(IOService *provider, IOOptionBits options, bool *defer);
  // Receives and store notification port when user process calls
  // IOConnectSetNotificationPort().
  IOReturn registerNotificationPort(mach_port_t port, UInt32 type,
                                    UInt32 refCon) override;
  // Returns the IOMemoryDescriptor when the user process calls
  // getMemoryDescriptor().
  IOReturn clientMemoryForType(UInt32 type, IOOptionBits *options,
                               IOMemoryDescriptor **memory) override;
 private:
  OsqueryDriverClassName *provider_;
};

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

// OSQuery I/O Kit kauth kernel extension. Additional information about the I/O
// kit architecture can be found here: http://goo.gl/2Mggbt.

#include <IOKit/IOService.h>
#include <IOKit/IOSharedDataQueue.h>
#include <sys/kauth.h>

#define OsqueryDriverClassName com_facebook_iokit_osquery

// I/O Kit drivers are subclassed from the IOService base class.
// The OSDeclareDefaultStructors macro defines C++ constructors.
class OsqueryDriverClassName : public IOService {
  OSDeclareDefaultStructors(com_facebook_iokit_osquery)

 public:
  // Starts driver functionality.
  bool start(IOService *provider) override;
  // Cleans up state creater by the start method.
  void stop(IOService *provider) override;
  // Sets the daemon notification port.
  IOReturn SetNotificationPort(mach_port_t port);
  // Sets the daemon notification port.
  IOMemoryDescriptor *GetSharedMemory();

 private:
  // Reference to the kauth listener.
  kauth_listener_t file_op_listener_;
  IOSharedDataQueue *data_queue_;
  IOMemoryDescriptor *memory_to_share_;
};

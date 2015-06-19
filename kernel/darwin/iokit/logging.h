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

// IOLog is the primary I/O Kit logging function: https://goo.gl/GLSA9e.

#include <IOKit/IOLib.h>

#ifdef DEBUG
#define LOGD(...) IOLog("D iokit-osquery: " __VA_ARGS__); IOLog("\n");
#else
#define LOGD(...)
#endif  // DEBUG
#define LOGI(...) IOLog("I iokit-osquery: " __VA_ARGS__); IOLog("\n")
#define LOGW(...) IOLog("W iokit-osquery: " __VA_ARGS__); IOLog("\n")
#define LOGE(...) IOLog("E iokit-osquery: " __VA_ARGS__); IOLog("\n")
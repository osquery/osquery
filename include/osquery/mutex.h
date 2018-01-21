/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#include <boost/thread/recursive_mutex.hpp>
#include <boost/thread/shared_mutex.hpp>

namespace osquery {

/// Helper alias for defining mutexes.
using Mutex = boost::shared_timed_mutex;

/// Helper alias for write locking a mutex.
using WriteLock = boost::unique_lock<Mutex>;

/// Helper alias for read locking a mutex.
using ReadLock = boost::shared_lock<Mutex>;

/// Helper alias for defining recursive mutexes.
using RecursiveMutex = boost::recursive_mutex;

/// Helper alias for write locking a recursive mutex.
using RecursiveLock = boost::unique_lock<boost::recursive_mutex>;

} // namespace osquery

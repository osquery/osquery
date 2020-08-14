/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <boost/thread/condition_variable.hpp>
#include <boost/thread/recursive_mutex.hpp>
#include <boost/thread/shared_mutex.hpp>

namespace osquery {

/// Helper alias for definition condition variables.
using ConditionVariable = boost::condition_variable_any;

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

/// Helper alias for upgrade locking a mutex.
using UpgradeLock = boost::upgrade_lock<Mutex>;

/// Helper alias for write locking an upgrade lock.
using WriteUpgradeLock = boost::upgrade_to_unique_lock<Mutex>;

} // namespace osquery

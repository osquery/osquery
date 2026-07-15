/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Precompiled header for the RocksDB third-party target.
//
// Headers were identified as the most expensive by ClangBuildAnalyzer.
//
// Include paths are resolved relative to the two PRIVATE include directories
// set on thirdparty_rocksdb:
//   ${library_root}            <- internal headers (db/*, memtable/*, etc.)
//   ${library_root}/include    <- public API (rocksdb/*.h)

#pragma once

// Standard library headers that are heavily used throughout RocksDB
#include <algorithm>
#include <atomic>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

// Public RocksDB API headers (available via ${library_root}/include)
#include <rocksdb/advanced_options.h>
#include <rocksdb/cache.h>
#include <rocksdb/comparator.h>
#include <rocksdb/db.h>
#include <rocksdb/env.h>
#include <rocksdb/options.h>
#include <rocksdb/slice.h>
#include <rocksdb/status.h>
#include <rocksdb/types.h>

// High-cost internal headers (available via ${library_root})
#include <db/dbformat.h>

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
// Headers were identified as the most expensive in ClangBuildAnalyzer output
// across the 303-file thirdparty_rocksdb build:
//
//   rocksdb/options.h          ~43 s  (242/303 inclusions, 0.18 s avg)
//   dbformat.h                 ~59 s  (163/303 inclusions, 0.36 s avg)
//   memtable.h                 ~32 s  ( 88/303 inclusions, 0.36 s avg)
//   memtable_list.h            ~55 s  ( 82/303 inclusions, 0.68 s avg)
//   column_family.h            ~61 s  ( 81/303 inclusions, 0.75 s avg)
//   db_impl.h                  ~63 s  ( 59/303 inclusions, 1.06 s avg)
//   version_set.h              ~28 s  ( 77/303 inclusions, 0.37 s avg)
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

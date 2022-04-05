/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// clang-format off
#include <sys/types.h>
#include <sys/stat.h>
// clang-format on

#ifndef WIN32
#include <unistd.h>
#endif

#include <set>
#include <thread>

#include <boost/filesystem.hpp>

#include <osquery/core/flags.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/hashing/hashing.h>
#include <osquery/logger/logger.h>
#include <osquery/core/tables.h>
#include <osquery/sql/dynamic_table_row.h>
#include <osquery/utils/mutex.h>
#include <osquery/utils/info/platform_type.h>
#include <osquery/worker/ipc/platform_table_container_ipc.h>
#include <osquery/worker/logging/glog/glog_logger.h>
#include <osquery/worker/logging/logger.h>

namespace osquery {

FLAG(bool,
     disable_hash_cache,
     false,
     "Cache calculated file hashes, re-calculate only if inode times change");

FLAG(uint32, hash_cache_max, 500, "Size of LRU file hash cache");

HIDDEN_FLAG(uint32,
            hash_delay,
            20,
            "Number of milliseconds to delay after hashing");

DECLARE_uint64(read_max);

namespace tables {

/// Clear this amount of rows every time cache eviction is triggered.
const size_t kHashCacheEvictSize{5};

/**
 * @brief Implements persistent in-memory caching of files' hashes.
 *
 * This cache has LRU eviction policy. The hash is recalculated
 * every time the mtime or size of the file changes.
 */
struct FileHashCache {
  /// The file's modification time, changes with a touch.
  time_t file_mtime;

  /// The file's serial or information number (inode).
  ino_t file_inode;

  /// The file's size.
  off_t file_size;

  /// For eviction, the last time this cache item was used.
  time_t cache_access_time;

  /// Cache content, the hashes.
  MultiHashes hashes;

  /// Cache index, the file path.
  std::string path;

  /// Comparison function for organizing the LRU heap.
  static bool greater(const FileHashCache* l, const FileHashCache* r) {
    return l->cache_access_time > r->cache_access_time;
  }

  /**
   * @brief Do-it-all access function.
   *
   * Maintains the cache of hash sums, stats file at path, if it has changed or
   * it is not present in cache calculates the hashes and caches the result.
   *
   * @param path the path of file to hash.
   * @param out stores the calculated hashes.
   *
   * @return true if succeeded, false if something went wrong.
   */
  static bool load(const std::string& path, MultiHashes& out, Logger& logger);
};

#if defined(WIN32)

#define stat _stat
#define strerror_r(e, buf, sz) strerror_s((buf), (sz), (e))

#endif

/**
 * @brief Checks the current stat output against the cached view.
 *
 * If the modified/altered time or the file's inode has changed then the hash
 * should be recalculated.
 */
static inline bool statInvalid(const struct stat& st, const FileHashCache& fh) {
  if (st.st_ino != fh.file_inode || st.st_mtime != fh.file_mtime) {
    // Most plausible case for modification detection.
    return true;
  }

  if (st.st_size != fh.file_size) {
    // Just in case there's tomfoolery.
    return true;
  }
  return false;
}

bool FileHashCache::load(const std::string& path,
                         MultiHashes& out,
                         Logger& logger) {
  // synchronize the access to cache
  static Mutex mx;
  // path => cache entry
  static std::unordered_map<std::string, FileHashCache> cache;
  // minheap on cache_access_time
  static std::vector<FileHashCache*> lru;

  WriteLock guard(mx);

  struct stat st;
  if (stat(path.c_str(), &st) != 0) {
    char buf[0x200] = {0};
    strerror_r(errno, buf, sizeof(buf));
    logger.log(google::GLOG_WARNING, "Cannot stat file: " + path + ": " + buf);
    return false;
  }

  auto entry = cache.find(path);
  if (entry == cache.end()) { // none, load
    if (cache.size() >= FLAGS_hash_cache_max) {
      // too large, evict
      for (size_t i = 0; i < kHashCacheEvictSize; ++i) {
        if (lru.empty()) {
          continue;
        }
        std::string key = lru[0]->path;
        std::pop_heap(lru.begin(), lru.end(), FileHashCache::greater);
        lru.pop_back();
        if (cache.find(key) != cache.end()) {
          cache.erase(key);
        }
      }
    }

    auto hashes = hashMultiFromFile(
        HASH_TYPE_MD5 | HASH_TYPE_SHA1 | HASH_TYPE_SHA256, path);
    FileHashCache rec = {st.st_mtime, // .file_mtime
                         st.st_ino, // .file_inode
                         st.st_size, // .file_size
                         time(nullptr), // .cache_access_time
                         std::move(hashes), // .hashes
                         path}; // .path
    cache[path] = std::move(rec);
    lru.push_back(&cache[path]);
    std::push_heap(lru.begin(), lru.end(), FileHashCache::greater);
    out = cache[path].hashes;
  } else if (statInvalid(st, entry->second)) { // changed, update
    auto hashes = hashMultiFromFile(
        HASH_TYPE_MD5 | HASH_TYPE_SHA1 | HASH_TYPE_SHA256, path);
    entry->second.cache_access_time = time(nullptr);
    entry->second.file_inode = st.st_ino;
    entry->second.file_mtime = st.st_mtime;
    entry->second.file_size = st.st_size;
    entry->second.hashes = std::move(hashes);
    std::make_heap(lru.begin(), lru.end(), FileHashCache::greater);
    out = entry->second.hashes;
  } else { // ok, got it
    out = entry->second.hashes;
    entry->second.cache_access_time = time(nullptr);
    std::make_heap(lru.begin(), lru.end(), FileHashCache::greater);
  }
  return true;
}

void genHashForFile(const std::string& path,
                    const std::string& dir,
                    QueryContext& context,
                    QueryData& results,
                    Logger& logger) {
  // Must provide the path, filename, directory separate from boost path->string
  // helpers to match any explicit (query-parsed) predicate constraints.
  auto tr = TableRowHolder(new DynamicTableRow());
  MultiHashes hashes;
  if (!FLAGS_disable_hash_cache) {
    FileHashCache::load(path, hashes, logger);
  } else {
    if (context.isCached(path)) {
      // Use the inner-query cache if the global hash cache is disabled.
      // This protects against hashing the same content twice in the same query.
      tr = context.getCache(path);
    } else {
      hashes = hashMultiFromFile(
          HASH_TYPE_MD5 | HASH_TYPE_SHA1 | HASH_TYPE_SHA256, path);
      std::this_thread::sleep_for(std::chrono::milliseconds(FLAGS_hash_delay));
    }
  }

  DynamicTableRow& r = *dynamic_cast<DynamicTableRow*>(tr.get());
  r["path"] = path;
  r["directory"] = dir;
  r["md5"] = std::move(hashes.md5);
  r["sha1"] = std::move(hashes.sha1);
  r["sha256"] = std::move(hashes.sha256);

  if (FLAGS_disable_hash_cache) {
    context.setCache(path, tr);
  }

  r["pid_with_namespace"] = "0";

  results.push_back(static_cast<Row>(r));
}

void expandFSPathConstraints(QueryContext& context,
                             const std::string& path_column_name,
                             std::set<std::string>& paths) {
  context.expandConstraints(
      path_column_name,
      LIKE,
      paths,
      ([&](const std::string& pattern, std::set<std::string>& out) {
        std::vector<std::string> patterns;
        auto status =
            resolveFilePattern(pattern, patterns, GLOB_ALL | GLOB_NO_CANON);
        if (status.ok()) {
          for (const auto& resolved : patterns) {
            out.insert(resolved);
          }
        }
        return status;
      }));
}

QueryData genHashImpl(QueryContext& context, Logger& logger) {
  QueryData results;
  boost::system::error_code ec;

  // The query must provide a predicate with constraints including path or
  // directory. We search for the parsed predicate constraints with the equals
  // operator.
  auto paths = context.constraints["path"].getAll(EQUALS);
  expandFSPathConstraints(context, "path", paths);

  // Iterate through the file paths, adding the hash results
  for (const auto& path_string : paths) {
    boost::filesystem::path path = path_string;
    if (!boost::filesystem::is_regular_file(path, ec)) {
      continue;
    }

    genHashForFile(
        path_string, path.parent_path().string(), context, results, logger);
  }

  // Now loop through constraints using the directory column constraint.
  auto directories = context.constraints["directory"].getAll(EQUALS);
  expandFSPathConstraints(context, "directory", directories);

  // Iterate over the directory paths
  for (const auto& directory_string : directories) {
    boost::filesystem::path directory = directory_string;
    if (!boost::filesystem::is_directory(directory, ec)) {
      continue;
    }

    // Iterate over the directory files and generate a hash for each regular
    // file.
    boost::filesystem::directory_iterator begin(directory), end;
    for (; begin != end; ++begin) {
      if (boost::filesystem::is_regular_file(begin->path(), ec)) {
        genHashForFile(
            begin->path().string(), directory_string, context, results, logger);
      }
    }
  }

  return results;
}

QueryData genHash(QueryContext& context) {
  if (hasNamespaceConstraint(context)) {
    return generateInNamespace(context, "hash", genHashImpl);
  } else {
    GLOGLogger logger;
    return genHashImpl(context, logger);
  }
}
} // namespace tables
} // namespace osquery

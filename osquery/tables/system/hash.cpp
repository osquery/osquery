/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <algorithm>
#include <iomanip>
#include <mutex>
#include <set>
#include <sstream>
#include <unordered_map>
#include <vector>

#include <errno.h>

// clang-format off
#include <sys/types.h>
#include <sys/stat.h>
// clang-format on

#ifndef WIN32
#include <unistd.h>
#endif

#include <openssl/md5.h>
#include <openssl/sha.h>

#include <boost/filesystem.hpp>

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/tables/system/hash.h"

namespace osquery {

FLAG(bool,
     enable_hash_cache,
     false,
     "Cache calculated file hashes, re-calculate only if file has changed");
FLAG(uint32, hash_cache_max, 500, "Cache hashes for upto this number of files");

// Clear this amount of rows every time eviction is triggered
#define HASH_CACHE_EVICT_SIZE 5

#define HASH_CHUNK_SIZE 4096

Hash::~Hash() {
  if (ctx_ != nullptr) {
    free(ctx_);
  }
}

Hash::Hash(HashType algorithm) : algorithm_(algorithm) {
  if (algorithm_ == HASH_TYPE_MD5) {
    length_ = MD5_DIGEST_LENGTH;
    ctx_ = static_cast<MD5_CTX*>(malloc(sizeof(MD5_CTX)));
    MD5_Init(static_cast<MD5_CTX*>(ctx_));
  } else if (algorithm_ == HASH_TYPE_SHA1) {
    length_ = SHA_DIGEST_LENGTH;
    ctx_ = static_cast<SHA_CTX*>(malloc(sizeof(SHA_CTX)));
    SHA1_Init(static_cast<SHA_CTX*>(ctx_));
  } else if (algorithm_ == HASH_TYPE_SHA256) {
    length_ = SHA256_DIGEST_LENGTH;
    ctx_ = static_cast<SHA256_CTX*>(malloc(sizeof(SHA256_CTX)));
    SHA256_Init(static_cast<SHA256_CTX*>(ctx_));
  } else {
    throw std::domain_error("Unknown hash function");
  }
}

void Hash::update(const void* buffer, size_t size) {
  if (algorithm_ == HASH_TYPE_MD5) {
    MD5_Update(static_cast<MD5_CTX*>(ctx_), buffer, size);
  } else if (algorithm_ == HASH_TYPE_SHA1) {
    SHA1_Update(static_cast<SHA_CTX*>(ctx_), buffer, size);
  } else if (algorithm_ == HASH_TYPE_SHA256) {
    SHA256_Update(static_cast<SHA256_CTX*>(ctx_), buffer, size);
  }
}

std::string Hash::digest() {
  std::vector<unsigned char> hash;
  hash.assign(length_, '\0');

  if (algorithm_ == HASH_TYPE_MD5) {
    MD5_Final(hash.data(), static_cast<MD5_CTX*>(ctx_));
  } else if (algorithm_ == HASH_TYPE_SHA1) {
    SHA1_Final(hash.data(), static_cast<SHA_CTX*>(ctx_));
  } else if (algorithm_ == HASH_TYPE_SHA256) {
    SHA256_Final(hash.data(), static_cast<SHA256_CTX*>(ctx_));
  }

  // The hash value is only relevant as a hex digest.
  std::stringstream digest;
  for (size_t i = 0; i < length_; i++) {
    digest << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
  }

  return digest.str();
}

std::string hashFromBuffer(HashType hash_type,
                           const void* buffer,
                           size_t size) {
  Hash hash(hash_type);
  hash.update(buffer, size);
  return hash.digest();
}

MultiHashes hashMultiFromFile(int mask, const std::string& path) {
  std::map<HashType, std::shared_ptr<Hash>> hashes = {
      {HASH_TYPE_MD5, std::make_shared<Hash>(HASH_TYPE_MD5)},
      {HASH_TYPE_SHA1, std::make_shared<Hash>(HASH_TYPE_SHA1)},
      {HASH_TYPE_SHA256, std::make_shared<Hash>(HASH_TYPE_SHA256)},
  };

  auto s = readFile(path,
                    0,
                    HASH_CHUNK_SIZE,
                    false,
                    true,
                    ([&hashes, &mask](std::string& buffer, size_t size) {
                      for (auto& hash : hashes) {
                        if (mask & hash.first) {
                          hash.second->update(&buffer[0], size);
                        }
                      }
                    }),
                    true);

  MultiHashes mh = {};
  if (!s.ok()) {
    return mh;
  }

  mh.mask = mask;
  if (mask & HASH_TYPE_MD5) {
    mh.md5 = hashes.at(HASH_TYPE_MD5)->digest();
  }
  if (mask & HASH_TYPE_SHA1) {
    mh.sha1 = hashes.at(HASH_TYPE_SHA1)->digest();
  }
  if (mask & HASH_TYPE_SHA256) {
    mh.sha256 = hashes.at(HASH_TYPE_SHA256)->digest();
  }
  return mh;
}

std::string hashFromFile(HashType hash_type, const std::string& path) {
  auto hashes = hashMultiFromFile(hash_type, path);
  if (hash_type == HASH_TYPE_MD5) {
    return hashes.md5;
  } else if (hash_type == HASH_TYPE_SHA1) {
    return hashes.sha1;
  } else {
    return hashes.sha256;
  }
}

/**
 * @brief Implements persistent in-memory caching of files' hashes.
 *
 * This cache has LRU eviction policy. The hash is recalculated
 * every time the mtime or size of the file changes.
 */
struct FileHashCache {
  time_t file_mtime;
  off_t file_size;
  time_t cache_access_time;
  MultiHashes hashes;
  std::string path;

  /// comparison function for organizing the LRU heap
  static bool greater(const FileHashCache* l, const FileHashCache* r) {
    return l->cache_access_time > r->cache_access_time;
  }
  /**
   * @brief Do-it-all access function.
   *
   * Maintains the cache of hash sums, stats file at path, if it has changed or
   * it is not present in cache calculates the hashes and caches the result
   *
   * @param path the path of file to hash
   * @param out stores the calculated hashes
   *
   * @return true if succeeded, false if something went wrong
   */
  static bool load(const std::string& path, MultiHashes& out);
};

#if defined(WIN32)

#define stat _stat

#endif

bool FileHashCache::load(const std::string& path, MultiHashes& out) {
  // synchronize the access to cache
  static Mutex mx;
  // path => cache entry
  static std::unordered_map<std::string, FileHashCache> cache;
  // minheap on cache_access_time
  static std::vector<FileHashCache*> lru;

  WriteLock guard(mx);

  struct stat st;
  if (stat(path.c_str(), &st) != 0) {
    LOG(WARNING) << "Cannot stat file: " << path << ": " << strerror(errno);
    return false;
  }

  auto entry = cache.find(path);
  if (entry == cache.end()) { // none, load
    if (cache.size() >= FLAGS_hash_cache_max) {
      // too large, evict
      for (size_t i = 0; i < HASH_CACHE_EVICT_SIZE; ++i) {
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
                         st.st_size, // .file_size
                         time(nullptr), // .cache_access_time
                         std::move(hashes), // .hashes
                         path}; // .path
    cache[path] = std::move(rec);
    lru.push_back(&cache[path]);
    std::push_heap(lru.begin(), lru.end(), FileHashCache::greater);
    out = cache[path].hashes;
  } else if (st.st_size != entry->second.file_size ||
             st.st_mtime != entry->second.file_mtime) { // changed, update
    auto hashes = hashMultiFromFile(
        HASH_TYPE_MD5 | HASH_TYPE_SHA1 | HASH_TYPE_SHA256, path);
    entry->second.cache_access_time = time(0);
    entry->second.file_mtime = st.st_mtime;
    entry->second.file_size = st.st_size;
    entry->second.hashes = std::move(hashes);
    std::make_heap(lru.begin(), lru.end(), FileHashCache::greater);
    out = entry->second.hashes;
  } else { // ok, got it
    out = entry->second.hashes;
    entry->second.cache_access_time = time(0);
    std::make_heap(lru.begin(), lru.end(), FileHashCache::greater);
  }
  return true;
}

void genHashForFile(const std::string& path,
                    const std::string& dir,
                    QueryContext& context,
                    QueryData& results) {
  // Must provide the path, filename, directory separate from boost path->string
  // helpers to match any explicit (query-parsed) predicate constraints.
  Row r;

  if (context.isCached(path)) {
    r = context.getCache(path);
  } else {
    MultiHashes hashes;
    if (FLAGS_enable_hash_cache) {
      FileHashCache::load(path, hashes);
    } else {
      hashes = hashMultiFromFile(
          HASH_TYPE_MD5 | HASH_TYPE_SHA1 | HASH_TYPE_SHA256, path);
    }

    r["path"] = path;
    r["directory"] = dir;
    r["md5"] = std::move(hashes.md5);
    r["sha1"] = std::move(hashes.sha1);
    r["sha256"] = std::move(hashes.sha256);
    context.setCache(path, r);
  }
  results.push_back(r);
}

namespace tables {

QueryData genHash(QueryContext& context) {
  QueryData results;
  boost::system::error_code ec;

  // The query must provide a predicate with constraints including path or
  // directory. We search for the parsed predicate constraints with the equals
  // operator.
  auto paths = context.constraints["path"].getAll(EQUALS);
  context.expandConstraints(
      "path",
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

  // Iterate through the file paths, adding the hash results
  for (const auto& path_string : paths) {
    boost::filesystem::path path = path_string;
    if (!boost::filesystem::is_regular_file(path, ec)) {
      continue;
    }

    genHashForFile(path_string, path.parent_path().string(), context, results);
  }

  // Now loop through constraints using the directory column constraint.
  auto directories = context.constraints["directory"].getAll(EQUALS);
  context.expandConstraints(
      "directory",
      LIKE,
      directories,
      ([&](const std::string& pattern, std::set<std::string>& out) {
        std::vector<std::string> patterns;
        auto status =
            resolveFilePattern(pattern, patterns, GLOB_FOLDERS | GLOB_NO_CANON);
        if (status.ok()) {
          for (const auto& resolved : patterns) {
            out.insert(resolved);
          }
        }
        return status;
      }));

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
            begin->path().string(), directory_string, context, results);
      }
    }
  }

  return results;
}
}
}

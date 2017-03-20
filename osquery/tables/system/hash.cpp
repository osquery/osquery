/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <iomanip>
#include <sstream>
#include <vector>

#include <boost/filesystem.hpp>

#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/tables/system/hash.h"

namespace osquery {

#ifdef __APPLE__
#import <CommonCrypto/CommonDigest.h>
#define __HASH_API(name) CC_##name
#else
#include <openssl/md5.h>
#include <openssl/sha.h>
#define __HASH_API(name) name

#define SHA1_DIGEST_LENGTH SHA_DIGEST_LENGTH
#define SHA1_CTX SHA_CTX
#endif

#define HASH_CHUNK_SIZE 4096

Hash::~Hash() {
  if (ctx_ != nullptr) {
    free(ctx_);
  }
}

Hash::Hash(HashType algorithm) : algorithm_(algorithm) {
  if (algorithm_ == HASH_TYPE_MD5) {
    length_ = __HASH_API(MD5_DIGEST_LENGTH);
    ctx_ = (__HASH_API(MD5_CTX)*)malloc(sizeof(__HASH_API(MD5_CTX)));
    __HASH_API(MD5_Init)((__HASH_API(MD5_CTX)*)ctx_);
  } else if (algorithm_ == HASH_TYPE_SHA1) {
    length_ = __HASH_API(SHA1_DIGEST_LENGTH);
    ctx_ = (__HASH_API(SHA1_CTX)*)malloc(sizeof(__HASH_API(SHA1_CTX)));
    __HASH_API(SHA1_Init)((__HASH_API(SHA1_CTX)*)ctx_);
  } else if (algorithm_ == HASH_TYPE_SHA256) {
    length_ = __HASH_API(SHA256_DIGEST_LENGTH);
    ctx_ = (__HASH_API(SHA256_CTX)*)malloc(sizeof(__HASH_API(SHA256_CTX)));
    __HASH_API(SHA256_Init)((__HASH_API(SHA256_CTX)*)ctx_);
  } else {
    throw std::domain_error("Unknown hash function");
  }
}

void Hash::update(const void* buffer, size_t size) {
  if (algorithm_ == HASH_TYPE_MD5) {
    __HASH_API(MD5_Update)((__HASH_API(MD5_CTX)*)ctx_, buffer, size);
  } else if (algorithm_ == HASH_TYPE_SHA1) {
    __HASH_API(SHA1_Update)((__HASH_API(SHA1_CTX)*)ctx_, buffer, size);
  } else if (algorithm_ == HASH_TYPE_SHA256) {
    __HASH_API(SHA256_Update)((__HASH_API(SHA256_CTX)*)ctx_, buffer, size);
  }
}

std::string Hash::digest() {
  std::vector<unsigned char> hash;
  hash.assign(length_, '\0');

  if (algorithm_ == HASH_TYPE_MD5) {
    __HASH_API(MD5_Final)(hash.data(), (__HASH_API(MD5_CTX)*)ctx_);
  } else if (algorithm_ == HASH_TYPE_SHA1) {
    __HASH_API(SHA1_Final)(hash.data(), (__HASH_API(SHA1_CTX)*)ctx_);
  } else if (algorithm_ == HASH_TYPE_SHA256) {
    __HASH_API(SHA256_Final)(hash.data(), (__HASH_API(SHA256_CTX)*)ctx_);
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
                    }));
  if (!s.ok()) {
    LOG(WARNING) << "Attempted to read file which exceeds flag limits";
  }

  MultiHashes mh;
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

namespace tables {

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
    auto hashes = hashMultiFromFile(
        HASH_TYPE_MD5 | HASH_TYPE_SHA1 | HASH_TYPE_SHA256, path);

    r["path"] = path;
    r["directory"] = dir;
    r["md5"] = std::move(hashes.md5);
    r["sha1"] = std::move(hashes.sha1);
    r["sha256"] = std::move(hashes.sha256);
    context.setCache(path, r);
  }
  results.push_back(r);
}

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

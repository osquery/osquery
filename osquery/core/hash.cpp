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

#include <osquery/filesystem.h>
#include <osquery/hash.h>
#include <osquery/logger.h>

namespace osquery {

#ifdef __APPLE__
#import <CommonCrypto/CommonDigest.h>
#define __HASH_API(name) CC_##name
#else
#include <openssl/sha.h>
#include <openssl/md5.h>
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

  readFile(path,
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
}

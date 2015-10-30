/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <iomanip>
#include <sstream>

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

#define HASH_CHUNK_SIZE 1024

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
  unsigned char hash[length_];

  if (algorithm_ == HASH_TYPE_MD5) {
    __HASH_API(MD5_Final)(hash, (__HASH_API(MD5_CTX)*)ctx_);
  } else if (algorithm_ == HASH_TYPE_SHA1) {
    __HASH_API(SHA1_Final)(hash, (__HASH_API(SHA1_CTX)*)ctx_);
  } else if (algorithm_ == HASH_TYPE_SHA256) {
    __HASH_API(SHA256_Final)(hash, (__HASH_API(SHA256_CTX)*)ctx_);
  }

  // The hash value is only relevant as a hex digest.
  std::stringstream digest;
  for (size_t i = 0; i < length_; i++) {
    digest << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
  }

  return digest.str();
}

std::string hashFromBuffer(HashType hash_type, const void* buffer, size_t size) {
  Hash hash(hash_type);
  hash.update(buffer, size);
  return hash.digest();
}

std::string hashFromFile(HashType hash_type, const std::string& path) {
  // Perform a dry-run of a file read without filling in any content.
  auto status = readFile(path);
  if (!status.ok()) {
    return "";
  }

  // Drop privileges to the user controlling the file.
  auto dropper = DropPrivileges::get();
  if (!dropper->dropToParent(path)) {
    return "";
  }

  Hash hash(hash_type);
  // Use the canonicalized path returned from a successful readFile dry-run.
  FILE* file = fopen(status.what().c_str(), "rb");
  if (file == nullptr) {
    VLOG(1) << "Cannot hash/open file: " << path;
    return "";
  }

  // Then call updates with read chunks.
  size_t bytes_read = 0;
  unsigned char buffer[HASH_CHUNK_SIZE];
  while ((bytes_read = fread(buffer, 1, HASH_CHUNK_SIZE, file))) {
    hash.update(buffer, bytes_read);
  }

  fclose(file);
  return hash.digest();
}
}

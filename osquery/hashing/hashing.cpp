/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <algorithm>
#include <iomanip>
#include <sstream>
#include <unordered_map>
#include <vector>

#include <openssl/md5.h>
#include <openssl/sha.h>

#include <osquery/filesystem/filesystem.h>
#include <osquery/hashing/hashing.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/base64.h>
#include <osquery/utils/info/platform_type.h>
#include <osquery/utils/status/status.h>

namespace osquery {

Hash::~Hash() {
  if (ctx_ != nullptr) {
    free(ctx_);
  }
}

Hash::Hash(HashType algorithm)
    : Hash::Hash(algorithm, HASH_ENCODING_TYPE_HEX) {}

Hash::Hash(HashType algorithm, HashEncodingType encoding)
    : algorithm_(algorithm), encoding_(encoding) {
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

Hash::Hash(Hash&& other) noexcept
    : algorithm_(other.algorithm_),
      encoding_(other.encoding_),
      ctx_(std::exchange(other.ctx_, nullptr)),
      length_(other.length_) {}

Hash& Hash::operator=(Hash&& other) noexcept {
  algorithm_ = other.algorithm_;
  encoding_ = other.encoding_;
  ctx_ = std::exchange(other.ctx_, nullptr);
  length_ = other.length_;

  return *this;
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

  if (encoding_ == HASH_ENCODING_TYPE_HEX) {
    std::stringstream digest;
    for (size_t i = 0; i < length_; i++) {
      digest << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return digest.str();
  } else if (encoding_ == HASH_ENCODING_TYPE_BASE64) {
    std::stringstream digest;
    for (size_t i = 0; i < length_; i++) {
      digest << hash[i];
    }
    return base64::encode(digest.str());
  }

  return "";
}

std::string hashFromBuffer(HashType hash_type,
                           const void* buffer,
                           size_t size) {
  Hash hash(hash_type);
  hash.update(buffer, size);
  return hash.digest();
}

MultiHashes hashMultiFromFile(int mask, const std::string& path) {
  std::map<HashType, Hash> hashes;
  hashes.emplace(HASH_TYPE_MD5, Hash{HASH_TYPE_MD5});
  hashes.emplace(HASH_TYPE_SHA1, Hash{HASH_TYPE_SHA1});
  hashes.emplace(HASH_TYPE_SHA256, Hash{HASH_TYPE_SHA256});

  auto status = readFile(path,
                         ([&hashes, &mask](std::string_view buffer) {
                           for (auto& hash : hashes) {
                             if (mask & hash.first) {
                               hash.second.update(buffer.data(), buffer.size());
                             }
                           }
                         }),
                         false);

  if (!status.ok()) {
    VLOG(1) << "Failed to hash " << path << ": " << status.getMessage();
    return {};
  }

  MultiHashes mh = {};

  mh.mask = mask;
  if (mask & HASH_TYPE_MD5) {
    mh.md5 = hashes.at(HASH_TYPE_MD5).digest();
  }
  if (mask & HASH_TYPE_SHA1) {
    mh.sha1 = hashes.at(HASH_TYPE_SHA1).digest();
  }
  if (mask & HASH_TYPE_SHA256) {
    mh.sha256 = hashes.at(HASH_TYPE_SHA256).digest();
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
} // namespace osquery

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
#include <osquery/utils/base64.h>
#include <osquery/utils/info/platform_type.h>
#include <osquery/utils/status/status.h>

namespace osquery {

/// The buffer read size from file IO to hashing structures.
const size_t kHashChunkSize{4096};

Hash::Hash(Hash&& other)
    : algorithm_(other.algorithm_),
      encoding_(other.encoding_),
      ctx_(other.ctx_),
      length_(other.length_) {
  // Reset the state of the original Hash object.
  other.ctx_ = nullptr;
}

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
    return base64::encode(std::string(hash.begin(), hash.end()));
  }

  return std::string();
}

std::string hashFromBuffer(HashType hash_type,
                           const void* buffer,
                           size_t size) {
  Hash hash(hash_type);
  hash.update(buffer, size);
  return hash.digest();
}

MultiHashes hashMultiFromFile(int mask, const std::string& path) {
  MultiHashes mh = {};
  std::vector<std::pair<Hash, std::string*>> hashes;
  if (mask & HASH_TYPE_MD5) {
    hashes.emplace_back(Hash(HASH_TYPE_MD5), &mh.md5);
  }
  if (mask & HASH_TYPE_SHA1) {
    hashes.emplace_back(Hash(HASH_TYPE_SHA1), &mh.sha1);
  }
  if (mask & HASH_TYPE_SHA256) {
    hashes.emplace_back(Hash(HASH_TYPE_SHA256), &mh.sha256);
  }

  auto blocking = isPlatform(PlatformType::TYPE_WINDOWS);
  auto s = readFile(path,
                    0,
                    kHashChunkSize,
                    false,
                    true,
                    ([&hashes](std::string& buffer, size_t size) {
                      for (auto& hash : hashes) {
                        hash.first.update(&buffer[0], size);
                      }
                    }),
                    blocking);
  if (!s.ok()) {
    return mh;
  }

  mh.mask = mask;
  for (auto& hash : hashes) {
    *hash.second = hash.first.digest();
  }
  return mh;
}

std::string hashFromFile(HashType hash_type, const std::string& path) {
  auto hashes = hashMultiFromFile(hash_type, path);
  if (hash_type == HASH_TYPE_MD5) {
    return std::move(hashes.md5);
  } else if (hash_type == HASH_TYPE_SHA1) {
    return std::move(hashes.sha1);
  } else {
    return std::move(hashes.sha256);
  }
}
} // namespace osquery

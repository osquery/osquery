/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <cstddef>
#include <cstdint>

namespace osquery {

/*
 * SipHash-2-4, a keyed pseudorandom function for untrusted input, from
 * "SipHash: a fast short-input PRF" by Jean-Philippe Aumasson and Daniel J.
 * Bernstein (Indocrypt 2012). This follows their reference implementation,
 * dedicated to the public domain, and is validated against its test vectors.
 *
 * The methods are defined in the header so callers can inline them: the hash
 * is used on hot paths, absorbing a few bytes at a time.
 */

/// Bytes are streamed in with update() and summarized into a 64-bit digest
/// with digest(). The 128-bit key is set at construction. Hashing the same
/// bytes under a different key produces unrelated digests, and an attacker
/// who does not know the key cannot craft inputs that collide.
class SipHash24 {
 public:
  SipHash24(uint64_t key0, uint64_t key1)
      : v0_(key0 ^ kMagic0),
        v1_(key1 ^ kMagic1),
        v2_(key0 ^ kMagic2),
        v3_(key1 ^ kMagic3) {}

  /// Absorb more bytes into the digest. The result does not depend on the
  /// host byte order or on how the input is split across calls.
  void update(const void* data, size_t size) {
    const auto* bytes = static_cast<const unsigned char*>(data);
    total_ += size;
    for (size_t i = 0; i < size; ++i) {
      buffer_ |= static_cast<uint64_t>(bytes[i]) << (8 * buffer_size_);
      if (++buffer_size_ == 8) {
        block(buffer_);
        buffer_ = 0;
        buffer_size_ = 0;
      }
    }
  }

  /// Produce the digest of everything absorbed so far. The finalization runs
  /// on a copy of the state, so this can be called more than once.
  uint64_t digest() const {
    uint64_t v0 = v0_;
    uint64_t v1 = v1_;
    uint64_t v2 = v2_;
    uint64_t v3 = v3_;

    // The length byte is followed by the partial block in the low bytes.
    uint64_t b = (total_ & 0xff) << 56 | buffer_;
    v3 ^= b;
    round(v0, v1, v2, v3);
    round(v0, v1, v2, v3);
    v0 ^= b;

    v2 ^= 0xff;
    round(v0, v1, v2, v3);
    round(v0, v1, v2, v3);
    round(v0, v1, v2, v3);
    round(v0, v1, v2, v3);
    return v0 ^ v1 ^ v2 ^ v3;
  }

 private:
  /// One SipRound.
  static void round(uint64_t& v0, uint64_t& v1, uint64_t& v2, uint64_t& v3) {
    v0 += v1;
    v1 = rotateLeft(v1, 13);
    v1 ^= v0;
    v0 = rotateLeft(v0, 32);

    v2 += v3;
    v3 = rotateLeft(v3, 16);
    v3 ^= v2;

    v0 += v3;
    v3 = rotateLeft(v3, 21);
    v3 ^= v0;

    v2 += v1;
    v1 = rotateLeft(v1, 17);
    v1 ^= v2;
    v2 = rotateLeft(v2, 32);
  }

  /// Compress one 64-bit block.
  void block(uint64_t m) {
    v3_ ^= m;
    round(v0_, v1_, v2_, v3_);
    round(v0_, v1_, v2_, v3_);
    v0_ ^= m;
  }

  static uint64_t rotateLeft(uint64_t value, int bits) {
    return (value << bits) | (value >> (64 - bits));
  }

  static constexpr uint64_t kMagic0 = 0x736f6d6570736575ULL;
  static constexpr uint64_t kMagic1 = 0x646f72616e646f6dULL;
  static constexpr uint64_t kMagic2 = 0x6c7967656e657261ULL;
  static constexpr uint64_t kMagic3 = 0x7465646279746573ULL;

  uint64_t v0_;
  uint64_t v1_;
  uint64_t v2_;
  uint64_t v3_;

  /// Partial block, bytes accumulated from the low end.
  uint64_t buffer_ = 0;

  /// Number of bytes currently in the partial block.
  size_t buffer_size_ = 0;

  /// Total number of bytes absorbed.
  uint64_t total_ = 0;
};

} // namespace osquery

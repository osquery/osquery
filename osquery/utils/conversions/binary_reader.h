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
#include <optional>
#include <string>
#include <string_view>

namespace osquery {

/**
 * @brief Bounds-checked binary reader over a non-owning byte view.
 *
 * Every read returns std::nullopt instead of throwing when the requested
 * range exceeds the buffer. Use at parser boundaries where input is
 * attacker-controlled (e.g., Windows shellbag REG_BINARY data).
 *
 * Lifetime: the underlying bytes must outlive the reader. Typically the
 * caller owns a std::string (the unhex result) and the reader is a view
 * over it.
 */
class BinaryReader {
 public:
  static constexpr std::size_t npos = std::string_view::npos;

  explicit BinaryReader(std::string_view bytes) noexcept : bytes_(bytes) {}

  std::size_t size() const noexcept { return bytes_.size(); }
  std::string_view raw() const noexcept { return bytes_; }

  bool in_bounds(std::size_t offset, std::size_t len) const noexcept {
    return offset <= bytes_.size() && bytes_.size() - offset >= len;
  }

  /// Byte slice [offset, offset+len). Nullopt if out of range.
  std::optional<std::string_view> bytes(std::size_t offset,
                                        std::size_t len) const noexcept {
    if (!in_bounds(offset, len)) {
      return std::nullopt;
    }
    return bytes_.substr(offset, len);
  }

  /// Byte slice from offset to end. Nullopt if offset > size.
  std::optional<std::string_view> bytes_from(std::size_t offset) const noexcept {
    if (offset > bytes_.size()) {
      return std::nullopt;
    }
    return bytes_.substr(offset);
  }

  std::optional<std::uint8_t> u8(std::size_t offset) const noexcept {
    if (!in_bounds(offset, 1)) {
      return std::nullopt;
    }
    return static_cast<std::uint8_t>(bytes_[offset]);
  }

  std::optional<std::uint16_t> u16_le(std::size_t offset) const noexcept {
    if (!in_bounds(offset, 2)) {
      return std::nullopt;
    }
    return static_cast<std::uint16_t>(
        static_cast<std::uint8_t>(bytes_[offset]) |
        (static_cast<std::uint16_t>(static_cast<std::uint8_t>(bytes_[offset + 1]))
         << 8));
  }

  std::optional<std::uint32_t> u32_le(std::size_t offset) const noexcept {
    if (!in_bounds(offset, 4)) {
      return std::nullopt;
    }
    return (static_cast<std::uint32_t>(static_cast<std::uint8_t>(bytes_[offset]))) |
           (static_cast<std::uint32_t>(static_cast<std::uint8_t>(bytes_[offset + 1])) << 8) |
           (static_cast<std::uint32_t>(static_cast<std::uint8_t>(bytes_[offset + 2])) << 16) |
           (static_cast<std::uint32_t>(static_cast<std::uint8_t>(bytes_[offset + 3])) << 24);
  }

  /// First occurrence of `needle` at or after `from`. npos if not found.
  std::size_t find(std::string_view needle,
                   std::size_t from = 0) const noexcept {
    return bytes_.find(needle, from);
  }

 private:
  std::string_view bytes_;
};

/**
 * @brief Drop every 0x00 byte from a byte view.
 *
 * Byte-space equivalent of the legacy shellbag parser's
 * `boost::erase_all("00")` (on the hex representation) followed by
 * `boost::algorithm::unhex`. For ASCII text encoded as UTF-16LE
 * (low byte = ASCII char, high byte = 0x00), this strips the high
 * bytes and reproduces the ASCII string.
 *
 * NOT a real UTF-16LE decoder: non-ASCII UTF-16 code units survive
 * as raw byte garbage in the output. Matching the legacy behavior
 * exactly is the goal; replacing this with a proper decoder is a
 * separate ticket (golden inputs for non-ASCII paths needed first).
 */
inline std::string stripNullBytes(std::string_view bytes) {
  std::string out;
  out.reserve(bytes.size());
  for (char c : bytes) {
    if (c != '\0') {
      out.push_back(c);
    }
  }
  return out;
}

} // namespace osquery

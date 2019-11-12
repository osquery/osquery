/**
 *  Copyright (c) 2019-present, osquery Foundation
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/logger.h>

#ifdef WIN32
#define STRNCPYS(DST, SRC, LEN, DSTLEN) strncpy_s(DST, DSTLEN, SRC, LEN)
#else
#define STRNCPYS(DST, SRC, LEN, DSTLEN) strncpy(DST, SRC, LEN)
#endif // else WIN32

namespace osquery {

/*
 * An event cache table can have about 50,000 rows.
 * Creating new Row objects or reusing a Row object and doing a Row.clear()
 * for every row in event cache table of 50,000 rows can add some overhead.
 * If most rows contain the same set of columns, keeping the same row
 * object, but overwriting the columns with the new values can save time.
 * About 0.1 seconds per query of 50,000 rows.  This is an object that
 * can help the binary row encoder repeatedly calculate the hash of
 * columns used by the current row.  The decoder can then compare the
 * hash value with previous row, to know if the row object needs to
 * be cleared, or leave as is because all columns will be overwritten.
 */
struct StringHash {
  StringHash(uint32_t maxlen = 1024) : _workingString(), _hasher() {
    _workingString.reserve(maxlen);
    _p = (char*)_workingString.data();
    _e = (char*)_workingString.data() + _workingString.capacity();
  }

  void clear() {
    _p = (char*)_workingString.data();
    _workingString.clear();
  }

  /*
   * Appends str to the end of the current working string.
   */
  void add(const std::string& str) {
    if (remaining() < (str.length() + 1)) {
      return;
    }
    STRNCPYS(_p, str.c_str(), str.length(), remaining());
    _p += str.length();
  }

  /*
   * Calculates the hash on current working string and
   * sets _hashValue.
   */
  void finalize() {
    _workingString.resize(_p - _workingString.data());
    _hashValue = (uint32_t)_hasher(_workingString);
  }

  /*
   * @return _hashValue Caller must call finalize() if any
   * changes have been made to working string.
   */
  uint32_t hash() {
    return _hashValue;
  }

  size_t remaining() {
    return (size_t)(_e - _p);
  }

 protected:
  std::string _workingString;
  char *_p, *_e;
  uint32_t _hashValue{0};
  std::hash<std::string> _hasher;
};

static inline size_t CalcSimpleStringMapEncodeSize(
    const std::map<std::string, std::string>& vec, StringHash& sh) {
  size_t len = 0;
  len += 4; // keyhash (24) | num keys (8)
  sh.clear();
  for (const auto& it : vec) {
    len += sizeof(uint32_t) + it.first.size() + it.second.size();
    sh.add(it.first);
  }
  sh.finalize();
  return len;
}

struct StringMapCoder {
  /*
   * Encodes each field in string map in the following
   * byte format.
   * NOTE: This encoding puts an artificial limit on the max size of an
   * event column value of 2^24  (16MB).
   *
   *   [32-bit header][name bytes][value bytes - if any]
   * where header dword is:
   *   [ name len (8-bits) |value length (24-bits)   ]
   * @param sm Row to encode
   * @param dest  Upon return, dest will be resized and populated with encoded
   * value.
   * @return true on error, false on success
   */
  bool encode(const std::map<std::string, std::string>& sm, std::string& dest) {
    size_t dest_size = CalcSimpleStringMapEncodeSize(sm, keyhasher_);
    if (dest_size == 0) {
      return true;
    }

    dest.reserve(dest_size + 1);
    dest.resize(dest_size);

    char* p = (char*)dest.c_str();

    // write keyhash | num keys
    *((uint32_t*)p) = (uint32_t)(keyhasher_.hash() << 8 | (uint8_t)sm.size());
    p += sizeof(uint32_t);

    for (const auto& it : sm) {
      auto namelen = it.first.size();
      auto valuelen = it.second.size();
      if (namelen >= 0x00FF) {
        LOG(WARNING) << "Row name too long:" << it.first;
        return true;
      }
      // write header
      *((uint32_t*)p) = (uint32_t)(namelen << 24 | valuelen);
      p += 4;
      STRNCPYS(p, it.first.c_str(), namelen, namelen + 1);
      p += namelen;
      if (valuelen > 0) {
        STRNCPYS(p, it.second.c_str(), valuelen, valuelen + 1);
        p += valuelen;
      }
    }
    return false;
  }

  /**
   * Decodes the output of SimpleStringMapEncode() and populates sm.
   * @param sm Should have empty()==true on enter.
   * @param encoded bytes string.
   * @return true on error, false on success.
   */
  bool decode(std::map<std::string, std::string>& sm,
              const std::string& encoded) {
    if (encoded.size() == 0) {
      return true;
    }

    char* p = (char*)encoded.c_str();
    char* end = p + encoded.size();

    // fields are prepended by a hash value of keys

    uint32_t keyHashValue = *((uint32_t*)p);
    p += 4;

    // optimization : if keys are the same in this row as previous, no need to
    // clear

    if (lastKeyHash_ != keyHashValue) {
      sm.clear();
    }
    lastKeyHash_ = keyHashValue;

    while (p < end) {
      uint32_t hdr = *((uint32_t*)p);
      p += 4;
      int name_len = hdr >> 24;
      int value_len = hdr & 0x00FFFFFF;
      if (name_len <= 0 || value_len < 0 || (p + name_len + value_len) > end) {
        return true;
      }
      char* v = p + name_len;
      sm[std::string(p, p + name_len)] = std::string(v, v + value_len);
      p += name_len + value_len;
    }
    return false;
  }

 protected:
  StringHash keyhasher_;
  uint32_t lastKeyHash_{0};
};

} // namespace osquery

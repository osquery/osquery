/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/utils/system/system.h>

#include <string>

#include <wtypes.h>

#include <osquery/utils/only_movable.h>

namespace osquery {

class Bstr : private only_movable {
 public:
  static Bstr fromString();

  Bstr() = default;
  ~Bstr();

  explicit Bstr(BSTR bs);

  Bstr(Bstr&& other);
  Bstr& operator=(Bstr&&);

  explicit operator bool() const {
    return !!bstr_;
  }

  BSTR get() const {
    return bstr_;
  }

  void reset(BSTR bstr = nullptr);

  BSTR release();

  BSTR* receiveAddress();

  size_t length() const;
  size_t byteLength() const;

 private:
  BSTR bstr_ = nullptr;
};

} // namespace osquery

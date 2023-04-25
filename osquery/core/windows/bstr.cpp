/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/utils/system/system.h>

#include <osquery/core/windows/bstr.h>

namespace osquery {

namespace {
static_assert(sizeof(Bstr) == sizeof(BSTR), "BstrSize");
}

Bstr::~Bstr() {
  // SysFreeString handles nullptr gracefully.
  ::SysFreeString(bstr_);
}

Bstr::Bstr(BSTR bs) : bstr_(bs) {}

Bstr::Bstr(Bstr&& other) : bstr_(other.bstr_) {
  other.bstr_ = nullptr;
}

Bstr& Bstr::operator=(Bstr&& other) {
  reset(other.release());
  return *this;
}

void Bstr::reset(BSTR bstr) {
  if (bstr != bstr_) {
    ::SysFreeString(bstr_);
    bstr_ = bstr;
  }
}

BSTR Bstr::release() {
  BSTR bstr = bstr_;
  bstr_ = nullptr;
  return bstr;
}

BSTR* Bstr::receiveAddress() {
  assert(!bstr_);
  return &bstr_;
}

size_t Bstr::length() const {
  return ::SysStringLen(bstr_);
}

size_t Bstr::byteLength() const {
  return ::SysStringByteLen(bstr_);
}

} // namespace osquery

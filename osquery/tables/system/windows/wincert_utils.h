/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <algorithm>
#include <ctime>
#include <iterator>
#include <string>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <wincrypt.h>

#include <boost/algorithm/hex.hpp>

namespace osquery {
namespace tables {

/**
 * @brief Helper to convert a byte range to a hex string.
 */
template <typename Iterator>
inline void toHexStr(Iterator begin,
                     Iterator end,
                     std::string& output,
                     bool littleEndian = false) {
  std::string s = std::string(begin, end);
  if (littleEndian) {
    boost::algorithm::hex(s.rbegin(), s.rend(), std::back_inserter(output));
  } else {
    boost::algorithm::hex(s, std::back_inserter(output));
  }
}

// Public API with mandatory null-checks on PCCERT_CONTEXT

std::wstring getCertificateSubjectName(PCCERT_CONTEXT certContext);
std::wstring getCertificateIssuerName(PCCERT_CONTEXT certContext);
std::wstring getCertificateCommonName(PCCERT_CONTEXT certContext);
std::wstring getCertificateSerialNumber(PCCERT_CONTEXT certContext);
std::wstring getCertificateSHA1Digest(PCCERT_CONTEXT certContext);
bool isCertificateAuthority(PCCERT_CONTEXT certContext);
bool isCertificateSelfSigned(PCCERT_CONTEXT certContext);
std::wstring getCertificateKeyUsage(PCCERT_CONTEXT certContext);
std::wstring getCertificateSigningAlgorithm(PCCERT_CONTEXT certContext);
std::wstring getCertificateKeyAlgorithm(PCCERT_CONTEXT certContext);
std::wstring getCertificateSubjectKeyID(PCCERT_CONTEXT certContext);
std::wstring getCertificateAuthorityKeyID(PCCERT_CONTEXT certContext);
DWORD getCertificateKeyStrength(PCCERT_CONTEXT certContext);
std::time_t getCertificateNotValidBefore(PCCERT_CONTEXT certContext);
std::time_t getCertificateNotValidAfter(PCCERT_CONTEXT certContext);

} // namespace tables
} // namespace osquery
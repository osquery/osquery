/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/optional.hpp>
#include <openssl/x509.h>

#include <map>
#include <string>

#include <osquery/core/core.h>

namespace osquery::tables {

boost::optional<std::string> generateCertificateSHA1Digest(X509* cert);
void getCertificateAttributes(X509* cert, bool& is_ca, bool& is_self_signed);
boost::optional<std::string> getCertificateKeyUsage(X509* cert);
boost::optional<std::string> getCertificateSerialNumber(X509* cert);
boost::optional<std::string> getCertificateAuthorityKeyID(X509* cert);
boost::optional<std::string> getCertificateSubjectKeyID(X509* cert);
boost::optional<std::string> getCertificateIssuerName(
    X509* cert, bool use_deprecated_output);
boost::optional<std::string> getCertificateSubjectName(
    X509* cert, bool use_deprecated_output);
boost::optional<std::string> getCertificateCommonName(X509* cert);
boost::optional<std::string> getCertificateSigningAlgorithm(X509* cert);
boost::optional<std::string> getCertificateKeyAlgorithm(X509* cert);
boost::optional<std::string> getCertificateKeyStregth(X509* cert);
boost::optional<std::time_t> getCertificateNotValidBefore(X509* cert);
boost::optional<std::time_t> getCertificateNotValidAfter(X509* cert);

} // namespace osquery::tables

/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <openssl/x509.h>

#include <map>
#include <string>

#include <osquery/core/core.h>

namespace osquery::tables {

// The flags are defined in openssl/x509v3.h,
// and its keys in crypto/x509v3/v3_bitst.c
// clang-format off
const std::map<uint32_t, std::string> kKeyUsageFlags = {
    {0x0001, "Encipher Only"},
    {0x0002, "CRL Sign"},
    {0x0004, "Key Cert Sign"},
    {0x0008, "Key Agreement"},
    {0x0010, "Data Encipherment"},
    {0x0020, "Key Encipherment"},
    {0x0040, "Non Repudiation"},
    {0x0080, "Digital Signature"},
    {0x8000, "Decipher Only"}};
// clang-format on

std::string genSHA1ForCertificate(X509* cert);
std::string genSerialForCertificate(X509* cert);

bool certificateIsCA(X509* cert);
bool certificateIsSelfSigned(X509* cert);

void genCommonName(X509* cert,
                   std::string& subject,
                   std::string& common_name,
                   std::string& issuer);

std::string genKIDProperty(const unsigned char* data, int len);

/// Generate the public key algorithm and signing algorithm.
void genAlgorithmProperties(X509* cert,
                            std::string& key,
                            std::string& sig,
                            std::string& size);

time_t genEpoch(ASN1_TIME* time);

std::string genKeyUsage(uint32_t flag);

std::string genHumanReadableDateTime(ASN1_TIME* time);

} // namespace osquery::tables

/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <osquery/core/tables.h>

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace osquery {
namespace tables {

// ---------------------------------------------------------------------------
// Forward-declare the internal parseEslData function exposed for testing.
// This function is defined at namespace scope in secureboot_certificates.cpp.
// ---------------------------------------------------------------------------
void parseEslData(const std::string& content,
                  bool revoked,
                  const std::string& path,
                  QueryData& results);

// ---------------------------------------------------------------------------
// Test fixture
// ---------------------------------------------------------------------------

class SecurebootCertificatesTests : public testing::Test {};

// ---------------------------------------------------------------------------
// Helper: Build a minimal ESL blob.
//
// Layout (bytes):
//   One EFI_SIGNATURE_LIST structure:
//       [0..15]  GUID (first byte controls X.509 detection)
//       [16..19] SignatureListSize  (LE uint32)
//       [20..23] SignatureHeaderSize (LE uint32, usually 0)
//       [24..27] SignatureSize      (LE uint32, includes 16-byte owner GUID)
//       [28..]   sig_payload bytes
// ---------------------------------------------------------------------------

static std::string buildEslBlob(uint8_t guid_first_byte,
                                uint32_t sig_size,
                                uint32_t sig_header_size,
                                const std::vector<uint8_t>& sig_payload) {
  const uint32_t sigs_area_size =
      sig_payload.empty() ? 0U : static_cast<uint32_t>(sig_payload.size());
  const uint32_t sig_list_size = 28U + sig_header_size + sigs_area_size;

  std::string blob(sig_list_size, '\x00');
  uint8_t* esl = reinterpret_cast<uint8_t*>(&blob[0]);

  esl[0] = guid_first_byte;

  // SignatureListSize [16..19] LE.
  esl[16] = static_cast<uint8_t>(sig_list_size & 0xFF);
  esl[17] = static_cast<uint8_t>((sig_list_size >> 8) & 0xFF);
  esl[18] = static_cast<uint8_t>((sig_list_size >> 16) & 0xFF);
  esl[19] = static_cast<uint8_t>((sig_list_size >> 24) & 0xFF);

  // SignatureHeaderSize [20..23] LE.
  esl[20] = static_cast<uint8_t>(sig_header_size & 0xFF);
  esl[21] = static_cast<uint8_t>((sig_header_size >> 8) & 0xFF);
  esl[22] = static_cast<uint8_t>((sig_header_size >> 16) & 0xFF);
  esl[23] = static_cast<uint8_t>((sig_header_size >> 24) & 0xFF);

  // SignatureSize [24..27] LE.
  esl[24] = static_cast<uint8_t>(sig_size & 0xFF);
  esl[25] = static_cast<uint8_t>((sig_size >> 8) & 0xFF);
  esl[26] = static_cast<uint8_t>((sig_size >> 16) & 0xFF);
  esl[27] = static_cast<uint8_t>((sig_size >> 24) & 0xFF);

  if (!sig_payload.empty()) {
    std::memcpy(
        esl + 28 + sig_header_size, sig_payload.data(), sig_payload.size());
  }

  return blob;
}

// ---------------------------------------------------------------------------
// Helper: Build an ESL blob containing a single real X.509 DER certificate.
// ---------------------------------------------------------------------------

static std::string buildX509EslBlob(const std::vector<uint8_t>& der_cert) {
  const uint32_t sig_size = static_cast<uint32_t>(16U + der_cert.size());
  const uint32_t sig_list_size = 28U + sig_size;

  std::string blob(sig_list_size, '\x00');
  uint8_t* esl = reinterpret_cast<uint8_t*>(&blob[0]);

  esl[0] = 0xa1U; // EFI_CERT_X509_GUID first byte

  // SignatureListSize
  esl[16] = static_cast<uint8_t>(sig_list_size & 0xFF);
  esl[17] = static_cast<uint8_t>((sig_list_size >> 8) & 0xFF);
  esl[18] = static_cast<uint8_t>((sig_list_size >> 16) & 0xFF);
  esl[19] = static_cast<uint8_t>((sig_list_size >> 24) & 0xFF);

  // SignatureSize
  esl[24] = static_cast<uint8_t>(sig_size & 0xFF);
  esl[25] = static_cast<uint8_t>((sig_size >> 8) & 0xFF);
  esl[26] = static_cast<uint8_t>((sig_size >> 16) & 0xFF);
  esl[27] = static_cast<uint8_t>((sig_size >> 24) & 0xFF);

  // 16-byte owner GUID is left as zeros; certificate bytes follow.
  std::memcpy(esl + 28 + 16, der_cert.data(), der_cert.size());

  return blob;
}

// ---------------------------------------------------------------------------
// Helper: Generate a minimal self-signed DER certificate using OpenSSL.
// ---------------------------------------------------------------------------

static std::vector<uint8_t> makeSelfSignedDerCert(
    const char* cn = "osquery-test-cert", int key_bits = 2048) {
  EVP_PKEY* pkey = EVP_PKEY_new();
  if (pkey == nullptr) {
    return {};
  }

  RSA* rsa = RSA_new();
  BIGNUM* exponent = BN_new();
  BN_set_word(exponent, RSA_F4);
  const int rc = RSA_generate_key_ex(rsa, key_bits, exponent, nullptr);
  BN_free(exponent);
  if (rc != 1) {
    RSA_free(rsa);
    EVP_PKEY_free(pkey);
    return {};
  }
  EVP_PKEY_assign_RSA(pkey, rsa); // pkey takes ownership of rsa

  X509* cert = X509_new();
  if (cert == nullptr) {
    EVP_PKEY_free(pkey);
    return {};
  }

  X509_set_version(cert, 2);
  ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
  X509_gmtime_adj(X509_get_notBefore(cert), 0);
  X509_gmtime_adj(X509_get_notAfter(cert), 365 * 24 * 3600L);
  X509_set_pubkey(cert, pkey);

  X509_NAME* name = X509_get_subject_name(cert);
  X509_NAME_add_entry_by_txt(name,
                             "CN",
                             MBSTRING_ASC,
                             reinterpret_cast<const unsigned char*>(cn),
                             -1,
                             -1,
                             0);
  X509_set_issuer_name(cert, name);

  if (X509_sign(cert, pkey, EVP_sha256()) == 0) {
    X509_free(cert);
    EVP_PKEY_free(pkey);
    return {};
  }

  int der_len = i2d_X509(cert, nullptr);
  if (der_len <= 0) {
    X509_free(cert);
    EVP_PKEY_free(pkey);
    return {};
  }

  std::vector<uint8_t> der(static_cast<std::size_t>(der_len));
  uint8_t* ptr = der.data();
  i2d_X509(cert, &ptr);

  X509_free(cert);
  EVP_PKEY_free(pkey);
  return der;
}

// ===========================================================================
// Edge-case tests (no real certificate required)
// ===========================================================================

// Content completely empty.
TEST_F(SecurebootCertificatesTests, ParseEslData_TooShort_Empty) {
  QueryData results;
  parseEslData("", false, "db", results);
  EXPECT_TRUE(results.empty());
}

// Content shorter than minimum ESL header (28 bytes).
TEST_F(SecurebootCertificatesTests, ParseEslData_TooShort_Partial) {
  const std::string blob(27, '\x00');
  QueryData results;
  parseEslData(blob, false, "db", results);
  EXPECT_TRUE(results.empty());
}

// ESL with a non-X.509 GUID should be skipped.
TEST_F(SecurebootCertificatesTests, ParseEslData_NonX509GuidSkipped) {
  // Use a first byte (0x26) that definitely doesn't match 0xA1.
  const std::string blob =
      buildEslBlob(0x26U, 20U, 0U, std::vector<uint8_t>(20, 0xAA));
  QueryData results;
  parseEslData(blob, false, "db", results);
  EXPECT_TRUE(results.empty());
}

// ESL with X.509 GUID but sig_size too small to even contain owner GUID (16
// bytes).
TEST_F(SecurebootCertificatesTests, ParseEslData_SigSizeTooSmall) {
  const std::string blob =
      buildEslBlob(0xa1U, 16U, 0U, std::vector<uint8_t>(16, 0x00));
  QueryData results;
  parseEslData(blob, false, "db", results);
  EXPECT_TRUE(results.empty());
}

// sig_list_size == 0 — parser must break immediately.
TEST_F(SecurebootCertificatesTests, ParseEslData_ZeroSigListSize) {
  std::string blob(28, '\x00');
  uint8_t* data = reinterpret_cast<uint8_t*>(&blob[0]);
  data[0] = 0xa1;
  // sig_list_size bytes [16..19] are all zero → sig_list_size == 0.
  QueryData results;
  parseEslData(blob, false, "db", results);
  EXPECT_TRUE(results.empty());
}

// sig_list_size extends past the buffer — must break.
TEST_F(SecurebootCertificatesTests, ParseEslData_OversizedSigListSize) {
  std::string blob(28, '\x00');
  uint8_t* data = reinterpret_cast<uint8_t*>(&blob[0]);
  data[0] = 0xa1;
  // Set sig_list_size = 0xFFFFFFFF.
  data[16] = 0xFF;
  data[17] = 0xFF;
  data[18] = 0xFF;
  data[19] = 0xFF;
  QueryData results;
  parseEslData(blob, false, "db", results);
  EXPECT_TRUE(results.empty());
}

// A non-zero sig_header_size means there is padding between the ESL header
// and the first EFI_SIGNATURE_DATA entry.  The parser must skip it correctly.
TEST_F(SecurebootCertificatesTests, ParseEslData_NonZeroSigHeaderSize) {
  const auto der_cert = makeSelfSignedDerCert();
  ASSERT_FALSE(der_cert.empty());

  // sig_size = 16 (owner GUID) + cert bytes
  const uint32_t sig_size = static_cast<uint32_t>(16U + der_cert.size());
  // sig_header_size = 8 bytes of padding inserted between the ESL header and
  // the first EFI_SIGNATURE_DATA entry.
  constexpr uint32_t kSigHeaderSize = 8U;

  // Build the signature payload: owner GUID (16 zeros) + cert.
  // The sig_header_size padding is handled by buildEslBlob.
  std::vector<uint8_t> payload(sig_size, 0x00);
  // Copy DER cert after owner GUID in the payload.
  std::memcpy(payload.data() + 16, der_cert.data(), der_cert.size());

  const std::string blob =
      buildEslBlob(0xa1U, sig_size, kSigHeaderSize, payload);

  QueryData results;
  parseEslData(blob, false, "db", results);

  // The cert should still be parsed correctly despite the header padding.
  ASSERT_EQ(results.size(), 1U);
  EXPECT_EQ(results[0].at("revoked"), "0");
  EXPECT_EQ(results[0].at("common_name"), "osquery-test-cert");
}

// ===========================================================================
// End-to-end tests with real self-signed DER certificates
// ===========================================================================

// A valid X.509 cert should produce exactly one row with expected field values.
TEST_F(SecurebootCertificatesTests, ParseEslData_ValidX509Cert_OneRow) {
  const auto der_cert = makeSelfSignedDerCert();
  ASSERT_FALSE(der_cert.empty()) << "Failed to generate test certificate";

  const std::string blob = buildX509EslBlob(der_cert);

  QueryData results;
  parseEslData(blob, /* revoked= */ false, "db", results);

  ASSERT_EQ(results.size(), 1U);

  const auto& row = results[0];
  EXPECT_EQ(row.at("revoked"), "0");
  EXPECT_EQ(row.at("path"), "db");
  EXPECT_EQ(row.at("common_name"), "osquery-test-cert");
  EXPECT_FALSE(row.at("sha1").empty());
  EXPECT_FALSE(row.at("serial").empty());
  EXPECT_EQ(row.at("self_signed"), "1");
  EXPECT_EQ(row.at("key_algorithm"), "RSA");
  EXPECT_EQ(row.at("key_strength"), "2048");
}

// Two concatenated ESL entries in the same blob should produce two rows.
TEST_F(SecurebootCertificatesTests, ParseEslData_TwoEntries_TwoRows) {
  const auto der_cert = makeSelfSignedDerCert();
  ASSERT_FALSE(der_cert.empty()) << "Failed to generate test certificate";

  const std::string single = buildX509EslBlob(der_cert);
  // Concatenate two ESL entries.
  const std::string blob = single + single;

  QueryData results;
  parseEslData(blob, /* revoked= */ true, "dbx", results);

  ASSERT_EQ(results.size(), 2U);
  EXPECT_EQ(results[0].at("revoked"), "1");
  EXPECT_EQ(results[1].at("revoked"), "1");
}

// revoked=true and the path string must be propagated into every row.
TEST_F(SecurebootCertificatesTests, ParseEslData_RevokedAndPathPropagated) {
  const auto der_cert = makeSelfSignedDerCert();
  ASSERT_FALSE(der_cert.empty());

  const std::string blob = buildX509EslBlob(der_cert);

  QueryData results;
  parseEslData(blob, /* revoked= */ true, "dbx", results);

  ASSERT_EQ(results.size(), 1U);
  EXPECT_EQ(results[0].at("revoked"), "1");
  EXPECT_EQ(results[0].at("path"), "dbx");
}

// revoked=false matches the "db" (allowlist) store.
TEST_F(SecurebootCertificatesTests, ParseEslData_DbStoreNotRevoked) {
  const auto der_cert = makeSelfSignedDerCert("osquery-db-cert");
  ASSERT_FALSE(der_cert.empty());

  const std::string blob = buildX509EslBlob(der_cert);

  QueryData results;
  parseEslData(blob, /* revoked= */ false, "db", results);

  ASSERT_EQ(results.size(), 1U);
  EXPECT_EQ(results[0].at("revoked"), "0");
  EXPECT_EQ(results[0].at("common_name"), "osquery-db-cert");
}

// ESL blob with an X.509 GUID but garbled cert bytes must not crash.
TEST_F(SecurebootCertificatesTests, ParseEslData_GarbageCertBytes_NoRow) {
  // Build a sig payload of 16 (owner GUID) + 32 (junk cert bytes).
  std::vector<uint8_t> payload(16 + 32, 0xDE);
  const uint32_t sig_size = static_cast<uint32_t>(payload.size());
  const std::string blob = buildEslBlob(0xa1U, sig_size, 0U, payload);

  QueryData results;
  ASSERT_NO_THROW(parseEslData(blob, false, "db", results));
  // The DER parse will fail on junk bytes, so no rows should be added.
  EXPECT_TRUE(results.empty());
}

// Verify that all expected column names are present in a result row.
TEST_F(SecurebootCertificatesTests, ParseEslData_AllColumnsPresent) {
  const auto der_cert = makeSelfSignedDerCert();
  ASSERT_FALSE(der_cert.empty());

  const std::string blob = buildX509EslBlob(der_cert);
  QueryData results;
  parseEslData(blob, false, "db", results);
  ASSERT_EQ(results.size(), 1U);

  const auto& row = results[0];
  static const std::vector<std::string> expected_columns = {
      "common_name",
      "subject",
      "issuer",
      "not_valid_before",
      "not_valid_after",
      "sha1",
      "serial",
      "revoked",
      "path",
      "is_ca",
      "self_signed",
      "key_usage",
      "authority_key_id",
      "subject_key_id",
      "signing_algorithm",
      "key_algorithm",
      "key_strength",
  };
  for (const auto& col : expected_columns) {
    EXPECT_TRUE(row.count(col) > 0) << "Missing column: " << col;
  }
}

} // namespace tables
} // namespace osquery

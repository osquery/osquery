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
#include <string>
#include <vector>

namespace osquery {
namespace tables {

// Forward-declare internal functions exposed for testing.
void parseEslData(const std::string& content,
                  const std::string& store,
                  const std::string& path,
                  QueryData& results);

class SecurebootCertificatesTests : public testing::Test {};

// ---------------------------------------------------------------------------
// parseEslData edge-case tests (no real certificate needed)
// ---------------------------------------------------------------------------

// Content shorter than the minimum (4 attribute bytes + 28 ESL header).
TEST_F(SecurebootCertificatesTests, parseEslData_too_short_empty) {
  QueryData results;
  parseEslData("", "db", "/fake/path", results);
  EXPECT_TRUE(results.empty());
}

TEST_F(SecurebootCertificatesTests, parseEslData_too_short_partial) {
  // Exactly 31 bytes — one byte less than 4 + 28.
  const std::string content(31, '\x00');
  QueryData results;
  parseEslData(content, "db", "/fake/path", results);
  EXPECT_TRUE(results.empty());
}

// Build a minimal ESL blob with the given GUID first byte and sig_size.
// Layout: [4 attr bytes] [28 ESL header] [sig_header_size bytes] [num_sigs *
// sig_size bytes]
static std::string buildEslBlob(uint8_t guid_first_byte,
                                uint32_t sig_size,
                                uint32_t sig_header_size,
                                const std::vector<uint8_t>& sig_payload) {
  // sig_header_size should be 0 for these tests.
  const uint32_t sigs_area_size =
      sig_payload.empty() ? 0U
                          : static_cast<uint32_t>(sig_payload.size());
  const uint32_t sig_list_size =
      28U + sig_header_size + sigs_area_size;

  std::string blob(4 + sig_list_size, '\x00');
  uint8_t* data = reinterpret_cast<uint8_t*>(&blob[0]);

  // EFI variable attributes (4 bytes, ignored by parser).
  data[0] = 0x07;
  data[1] = 0x00;
  data[2] = 0x00;
  data[3] = 0x00;

  // ESL header starts at byte 4.
  uint8_t* esl = data + 4;

  // GUID bytes [0..15] — first byte controls X.509 detection.
  esl[0] = guid_first_byte;
  // Remaining GUID bytes are zero (don't affect current logic).

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

  // Copy signature payload (owner GUID + cert bytes) after the header.
  if (!sig_payload.empty()) {
    std::memcpy(esl + 28 + sig_header_size,
                sig_payload.data(),
                sig_payload.size());
  }

  return blob;
}

// ESL with a non-X.509 GUID — must be skipped entirely.
TEST_F(SecurebootCertificatesTests, parseEslData_non_x509_guid_skipped) {
  // Any first byte that is NOT 0xa1 selects a non-X509 entry type.
  const std::string blob = buildEslBlob(0x26U, 20U, 0U, std::vector<uint8_t>(20, 0xAA));
  QueryData results;
  parseEslData(blob, "db", "/fake/path", results);
  EXPECT_TRUE(results.empty());
}

// ESL with X.509 GUID but sig_size <= 16 (too small for owner GUID) — skipped.
TEST_F(SecurebootCertificatesTests, parseEslData_sig_size_too_small) {
  // sig_size = 16 means zero cert bytes after the 16-byte owner GUID → skip.
  const std::string blob = buildEslBlob(0xa1U, 16U, 0U, std::vector<uint8_t>(16, 0x00));
  QueryData results;
  parseEslData(blob, "db", "/fake/path", results);
  EXPECT_TRUE(results.empty());
}

// ESL header with sig_list_size == 0 — must break immediately.
TEST_F(SecurebootCertificatesTests, parseEslData_zero_sig_list_size) {
  // Construct a blob where the sig_list_size field in the header is 0.
  std::string blob(4 + 28, '\x00');
  uint8_t* data = reinterpret_cast<uint8_t*>(&blob[0]);
  data[0] = 0x07; // EFI attr bytes
  data[4] = 0xa1; // X.509 GUID first byte
  // sig_list_size at offsets 20-23 (relative to blob start: 4+16=20) is 0.
  // All zeros → sig_list_size == 0 → parser breaks.
  QueryData results;
  parseEslData(blob, "db", "/fake/path", results);
  EXPECT_TRUE(results.empty());
}

// sig_list_size extends beyond buffer — must break.
TEST_F(SecurebootCertificatesTests, parseEslData_oversized_sig_list_size) {
  std::string blob(4 + 28, '\x00');
  uint8_t* data = reinterpret_cast<uint8_t*>(&blob[0]);
  data[0] = 0x07;
  data[4] = 0xa1;
  // Set sig_list_size = 0xFFFFFFFF, which clearly extends past the buffer.
  data[4 + 16] = 0xFF;
  data[4 + 17] = 0xFF;
  data[4 + 18] = 0xFF;
  data[4 + 19] = 0xFF;
  QueryData results;
  parseEslData(blob, "db", "/fake/path", results);
  EXPECT_TRUE(results.empty());
}

// ---------------------------------------------------------------------------
// Helper: generate a minimal self-signed DER certificate using OpenSSL.
// Returns the raw DER bytes, or empty on failure.
// ---------------------------------------------------------------------------
static std::vector<uint8_t> makeSelfSignedDerCert() {
  // Generate a 2048-bit RSA key.
  EVP_PKEY* pkey = EVP_PKEY_new();
  if (pkey == nullptr) {
    return {};
  }

  RSA* rsa = RSA_new();
  BIGNUM* exponent = BN_new();
  BN_set_word(exponent, RSA_F4);
  const int rc = RSA_generate_key_ex(rsa, 2048, exponent, nullptr);
  BN_free(exponent);
  if (rc != 1) {
    RSA_free(rsa);
    EVP_PKEY_free(pkey);
    return {};
  }
  EVP_PKEY_assign_RSA(pkey, rsa); // pkey takes ownership

  X509* cert = X509_new();
  if (cert == nullptr) {
    EVP_PKEY_free(pkey);
    return {};
  }

  // Version 3 (value 2), serial number 1.
  X509_set_version(cert, 2);
  ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);

  // Valid from now for one year.
  X509_gmtime_adj(X509_get_notBefore(cert), 0);
  X509_gmtime_adj(X509_get_notAfter(cert), 365 * 24 * 3600L);

  X509_set_pubkey(cert, pkey);

  // Subject and issuer: CN=osquery-test-cert
  X509_NAME* name = X509_get_subject_name(cert);
  X509_NAME_add_entry_by_txt(name,
                             "CN",
                             MBSTRING_ASC,
                             reinterpret_cast<const unsigned char*>(
                                 "osquery-test-cert"),
                             -1,
                             -1,
                             0);
  X509_set_issuer_name(cert, name);

  // Self-sign with SHA-256.
  if (X509_sign(cert, pkey, EVP_sha256()) == 0) {
    X509_free(cert);
    EVP_PKEY_free(pkey);
    return {};
  }

  // Encode to DER.
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

// Build an ESL blob containing a single X.509 entry wrapping the given DER cert.
static std::string buildX509EslBlob(const std::vector<uint8_t>& der_cert,
                                    const std::string& store) {
  // sig_size = 16 (owner GUID) + cert bytes.
  const uint32_t sig_size =
      static_cast<uint32_t>(16U + der_cert.size());
  // sig_list_size = 28 (ESL header) + sig_size.
  const uint32_t sig_list_size = 28U + sig_size;

  std::string blob(4 + sig_list_size, '\x00');
  uint8_t* data = reinterpret_cast<uint8_t*>(&blob[0]);

  // EFI variable attribute bytes.
  data[0] = 0x07;

  // ESL header at offset 4.
  uint8_t* esl = data + 4;

  // EFI_CERT_X509_GUID first byte (0xa1).
  esl[0] = 0xa1U;

  // SignatureListSize.
  esl[16] = static_cast<uint8_t>(sig_list_size & 0xFF);
  esl[17] = static_cast<uint8_t>((sig_list_size >> 8) & 0xFF);
  esl[18] = static_cast<uint8_t>((sig_list_size >> 16) & 0xFF);
  esl[19] = static_cast<uint8_t>((sig_list_size >> 24) & 0xFF);

  // SignatureHeaderSize = 0 (already zero from fill).

  // SignatureSize.
  esl[24] = static_cast<uint8_t>(sig_size & 0xFF);
  esl[25] = static_cast<uint8_t>((sig_size >> 8) & 0xFF);
  esl[26] = static_cast<uint8_t>((sig_size >> 16) & 0xFF);
  esl[27] = static_cast<uint8_t>((sig_size >> 24) & 0xFF);

  // SignatureOwner GUID (16 zero bytes) followed by the DER cert.
  // esl + 28 = start of the single EFI_SIGNATURE_DATA entry.
  // Bytes [0..15] = owner GUID (left as zero).
  // Bytes [16..] = DER certificate.
  std::memcpy(esl + 28 + 16, der_cert.data(), der_cert.size());

  return blob;
}

// ---------------------------------------------------------------------------
// parseEslData end-to-end test with a real self-signed DER certificate.
// ---------------------------------------------------------------------------

TEST_F(SecurebootCertificatesTests, parseEslData_valid_x509_cert_one_row) {
  const auto der_cert = makeSelfSignedDerCert();
  ASSERT_FALSE(der_cert.empty()) << "Failed to generate test certificate";

  const std::string blob = buildX509EslBlob(der_cert, "db");

  QueryData results;
  parseEslData(blob, "db", "/sys/firmware/efi/efivars/db-test", results);

  ASSERT_EQ(results.size(), 1U);

  const auto& row = results[0];

  EXPECT_EQ(row.at("store"), "db");
  EXPECT_EQ(row.at("path"), "/sys/firmware/efi/efivars/db-test");
  EXPECT_EQ(row.at("common_name"), "osquery-test-cert");
  EXPECT_FALSE(row.at("sha1").empty());
  EXPECT_FALSE(row.at("serial").empty());
  EXPECT_EQ(row.at("self_signed"), "1");
  EXPECT_EQ(row.at("key_algorithm"), "rsaEncryption");
  EXPECT_EQ(row.at("key_strength"), "2048");
}

// Two concatenated ESL entries in the same blob → two rows.
TEST_F(SecurebootCertificatesTests, parseEslData_two_entries_two_rows) {
  const auto der_cert = makeSelfSignedDerCert();
  ASSERT_FALSE(der_cert.empty()) << "Failed to generate test certificate";

  const std::string single = buildX509EslBlob(der_cert, "db");
  // Concatenate two ESL entries: the first blob (with its 4 attr bytes) followed
  // by a second ESL entry (without attr bytes, since a real EFI variable has
  // only one set of attribute bytes at the start).
  const std::string blob = single + single.substr(4);

  QueryData results;
  parseEslData(blob, "dbx", "/sys/firmware/efi/efivars/dbx-test", results);

  ASSERT_EQ(results.size(), 2U);
  EXPECT_EQ(results[0].at("store"), "dbx");
  EXPECT_EQ(results[1].at("store"), "dbx");
}

// Store name and path are propagated correctly into rows.
TEST_F(SecurebootCertificatesTests, parseEslData_store_and_path_set) {
  const auto der_cert = makeSelfSignedDerCert();
  ASSERT_FALSE(der_cert.empty());

  const std::string blob = buildX509EslBlob(der_cert, "dbx");

  QueryData results;
  parseEslData(blob, "dbx", "/sys/firmware/efi/efivars/dbx-abcdef", results);

  ASSERT_EQ(results.size(), 1U);
  EXPECT_EQ(results[0].at("store"), "dbx");
  EXPECT_EQ(results[0].at("path"), "/sys/firmware/efi/efivars/dbx-abcdef");
}

} // namespace tables
} // namespace osquery

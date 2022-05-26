/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <openssl/x509v3.h>

#include <array>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <string>

#include <osquery/core/core.h>
#include <osquery/tables/system/posix/openssl_utils.h>

namespace osquery::tables {

namespace {

// The flags are defined in openssl/x509v3.h,
// and its keys in crypto/x509v3/v3_bitst.c
const std::map<uint32_t, std::string> kKeyUsageFlagList = {
    {0x0001, "Encipher Only"},
    {0x0002, "CRL Sign"},
    {0x0004, "Key Cert Sign"},
    {0x0008, "Key Agreement"},
    {0x0010, "Data Encipherment"},
    {0x0020, "Key Encipherment"},
    {0x0040, "Non Repudiation"},
    {0x0080, "Digital Signature"},
    {0x8000, "Decipher Only"}};

using UniqueBIO = std::unique_ptr<BIO, int (*)(BIO*)>;

UniqueBIO createUniqueBIO() {
  UniqueBIO unique_mem_bio(nullptr, BIO_free);

  auto mem_bio = BIO_new(BIO_s_mem());
  if (mem_bio != nullptr) {
    unique_mem_bio.reset(mem_bio);
  }

  return unique_mem_bio;
}

std::string convertBinaryDigestToString(const unsigned char* binary_digest,
                                        unsigned int length) {
  std::stringstream string_digest;
  for (unsigned int i = 0; i < length; i++) {
    string_digest << std::setw(2) << std::hex << std::setfill('0')
                  << static_cast<int>(binary_digest[i]);
  }

  return string_digest.str();
}

boost::optional<std::string> getMemoryBackedBIOContentsAsString(BIO* bio) {
  char* buffer_ptr{nullptr};
  auto buffer_size = BIO_get_mem_data(bio, &buffer_ptr);
  if (buffer_size < 0) {
    return boost::none;
  }

  return std::string(buffer_ptr, buffer_size);
}

boost::optional<std::string> convertAsn1TimeToString(
    const ASN1_TIME* asn1_time) {
  auto unique_mem_bio = createUniqueBIO();
  if (unique_mem_bio == nullptr) {
    return boost::none;
  }

  // ANS1_TIME_print's format is: Mon DD HH:MM:SS YYYY GMT
  // e.g. Jan 1 00:00:00 1970 GMT (always GMT)
  if (ASN1_TIME_print(unique_mem_bio.get(), asn1_time) == 0) {
    return boost::none;
  }

  return getMemoryBackedBIOContentsAsString(unique_mem_bio.get());
}

boost::optional<std::time_t> convertAsn1TimeToEpochTime(
    const ASN1_TIME* asn1_time) {
  auto opt_string_time = convertAsn1TimeToString(asn1_time);
  if (!opt_string_time.has_value()) {
    return boost::none;
  }

  const auto& string_time = opt_string_time.value();

  // b := abbr month, e := day with leading space instead of leading zero
  struct tm tm {};
  if (strptime(string_time.c_str(), "%b %e %H:%M:%S %Y %Z", &tm) == nullptr) {
    return boost::none;
  }

  // Don't set DST, since strptime() doesn't.
  // Let mktime() determine whether DST in effect
  tm.tm_isdst = -1;

  auto epoch = std::mktime(&tm);
  if (epoch == -1) {
    return boost::none;
  }

  return epoch;
}

boost::optional<std::string> convertX509NameToString(
    const X509_NAME* name, bool use_deprecated_output) {
  if (use_deprecated_output) {
    auto string_name = X509_NAME_oneline(name, nullptr, 0);
    if (string_name == nullptr) {
      return boost::none;
    }

    std::string output(string_name);
    OPENSSL_free(string_name);

    return output;

  } else {
    auto unique_mem_bio = createUniqueBIO();
    if (unique_mem_bio == nullptr) {
      return boost::none;
    }

    if (X509_NAME_print_ex(unique_mem_bio.get(), name, 0, XN_FLAG_ONELINE) ==
        -1) {
      return boost::none;
    }

    return getMemoryBackedBIOContentsAsString(unique_mem_bio.get());
  }
}

} // namespace

boost::optional<std::string> generateCertificateSHA1Digest(X509* cert) {
  std::array<unsigned char, EVP_MAX_MD_SIZE> binary_digest_buffer{};
  unsigned int binary_digest_length{};

  if (X509_digest(cert,
                  EVP_sha1(),
                  binary_digest_buffer.data(),
                  &binary_digest_length) == 0) {
    return boost::none;
  }

  return convertBinaryDigestToString(binary_digest_buffer.data(),
                                     binary_digest_length);
}

void getCertificateAttributes(X509* cert, bool& is_ca, bool& is_self_signed) {
  is_ca = X509_check_ca(cert) > 0;
  is_self_signed = (X509_check_issued(cert, cert) == X509_V_OK);
}

boost::optional<std::string> getCertificateKeyUsage(X509* cert) {
  auto key_usage_flags = X509_get_key_usage(cert);
  if (key_usage_flags == UINT32_MAX) {
    return boost::none;
  }

  std::string output;

  for (const auto& key : kKeyUsageFlagList) {
    const auto& usage_flag = key.first;
    if ((key_usage_flags & usage_flag) == 0) {
      continue;
    }

    if (!output.empty()) {
      output += ", ";
    }

    const auto& usage_name = key.second;
    output += usage_name;
  }

  return output;
}

boost::optional<std::string> getCertificateSerialNumber(X509* cert) {
  auto serial = X509_get_serialNumber(cert);
  if (serial == nullptr) {
    return boost::none;
  }

  auto big_num_serial = ASN1_INTEGER_to_BN(serial, nullptr);
  if (big_num_serial == nullptr) {
    return boost::none;
  }

  char* string_serial = BN_bn2hex(big_num_serial);
  BN_free(big_num_serial);

  if (string_serial == nullptr) {
    return boost::none;
  }

  std::string output(string_serial);
  OPENSSL_free(string_serial);

  return output;
}

boost::optional<std::string> getCertificateAuthorityKeyID(X509* cert) {
  auto cert_key_id = X509_get0_authority_key_id(cert);
  if (cert_key_id == nullptr) {
    return boost::none;
  }

  return convertBinaryDigestToString(cert_key_id->data, cert_key_id->length);
}

boost::optional<std::string> getCertificateSubjectKeyID(X509* cert) {
  auto cert_key_id = X509_get0_subject_key_id(cert);
  if (cert_key_id == nullptr) {
    return boost::none;
  }

  return convertBinaryDigestToString(cert_key_id->data, cert_key_id->length);
}

boost::optional<std::string> getCertificateIssuerName(
    X509* cert, bool use_deprecated_output) {
  auto issuer_name = X509_get_issuer_name(cert);
  if (issuer_name == nullptr) {
    return boost::none;
  }

  return convertX509NameToString(issuer_name, use_deprecated_output);
}

boost::optional<std::string> getCertificateSubjectName(
    X509* cert, bool use_deprecated_output) {
  auto subject_name = X509_get_subject_name(cert);
  if (subject_name == nullptr) {
    return boost::none;
  }

  return convertX509NameToString(subject_name, use_deprecated_output);
}

boost::optional<std::string> getCertificateCommonName(X509* cert) {
  static const auto kCnNid{OBJ_txt2nid("CN")};

  auto subject_name = X509_get_subject_name(cert);
  if (subject_name == nullptr) {
    return boost::none;
  }

  int common_name_index = X509_NAME_get_index_by_NID(subject_name, kCnNid, -1);
  if (common_name_index == -1) {
    return boost::none;
  }

  auto common_name_entry = X509_NAME_get_entry(subject_name, common_name_index);
  if (common_name_entry == nullptr) {
    return boost::none;
  }

  auto asn1_str_common_name = X509_NAME_ENTRY_get_data(common_name_entry);
  if (asn1_str_common_name == nullptr) {
    return boost::none;
  }

  auto common_name_string_buf = ASN1_STRING_get0_data(asn1_str_common_name);
  if (common_name_string_buf == nullptr) {
    return boost::none;
  }

  auto common_name_string_len =
      static_cast<std::size_t>(ASN1_STRING_length(asn1_str_common_name));
  if (common_name_string_len == 0) {
    return boost::none;
  }

  std::string output;
  output.resize(common_name_string_len);

  std::memcpy(&output[0], common_name_string_buf, common_name_string_len);
  return output;
}

boost::optional<std::string> getCertificateSigningAlgorithm(X509* cert) {
  auto signature_nid = X509_get_signature_nid(cert);
  if (signature_nid == NID_undef) {
    return boost::none;
  }

  auto signing_algorithm = OBJ_nid2ln(signature_nid);
  if (signing_algorithm == nullptr) {
    return boost::none;
  }

  return std::string(signing_algorithm);
}

boost::optional<std::string> getCertificateKeyAlgorithm(X509* cert) {
  auto pub_key = X509_get_X509_PUBKEY(cert);
  if (pub_key == nullptr) {
    return boost::none;
  }

  ASN1_OBJECT* public_key_params{nullptr};
  if (X509_PUBKEY_get0_param(
          &public_key_params, nullptr, nullptr, nullptr, pub_key) == 0) {
    return boost::none;
  }

  if (public_key_params == nullptr) {
    return boost::none;
  }

  auto nid = OBJ_obj2nid(public_key_params);
  if (nid == NID_undef) {
    return boost::none;
  }

  auto key_algorithm = OBJ_nid2ln(nid);
  if (key_algorithm == nullptr) {
    return boost::none;
  }

  return std::string(key_algorithm);
}

boost::optional<std::string> getCertificateKeyStregth(X509* cert) {
  auto pub_key = X509_get_X509_PUBKEY(cert);
  if (pub_key == nullptr) {
    return boost::none;
  }

  ASN1_OBJECT* public_key_params{nullptr};
  if (X509_PUBKEY_get0_param(
          &public_key_params, nullptr, nullptr, nullptr, pub_key) == 0) {
    return boost::none;
  }

  if (public_key_params == nullptr) {
    return boost::none;
  }

  auto nid = OBJ_obj2nid(public_key_params);
  if (nid == NID_undef) {
    return boost::none;
  }

  std::unique_ptr<EVP_PKEY, void (*)(EVP_PKEY*)> unique_evp_key(nullptr,
                                                                EVP_PKEY_free);

  {
    auto evp_pub_key = X509_get_pubkey(cert);
    if (evp_pub_key == nullptr) {
      return boost::none;
    }

    unique_evp_key.reset(evp_pub_key);
  }

  if (nid == NID_rsaEncryption || nid == NID_dsa) {
    auto key_size = EVP_PKEY_size(unique_evp_key.get());
    if (key_size == 0) {
      return boost::none;
    }

    return std::to_string(key_size * 8);

  } else if (nid == NID_X9_62_id_ecPublicKey) {
    auto ec_key = EVP_PKEY_get0_EC_KEY(unique_evp_key.get());
    if (ec_key == nullptr) {
      return boost::none;
    }

    auto ec_group = EC_KEY_get0_group(ec_key);
    if (ec_group == nullptr) {
      return boost::none;
    }

    auto curve_name_id = EC_GROUP_get_curve_name(ec_group);
    if (curve_name_id == NID_undef) {
      return boost::none;
    }

    auto curve_name = OBJ_nid2ln(curve_name_id);
    if (curve_name == nullptr) {
      return boost::none;
    }

    return std::string(curve_name);

  } else {
    return boost::none;
  }
}

boost::optional<std::time_t> getCertificateNotValidBefore(X509* cert) {
  auto not_before = X509_get_notBefore(cert);
  if (not_before == nullptr) {
    return boost::none;
  }

  return convertAsn1TimeToEpochTime(not_before);
}

boost::optional<std::time_t> getCertificateNotValidAfter(X509* cert) {
  auto not_after = X509_get_notAfter(cert);
  if (not_after == nullptr) {
    return boost::none;
  }

  return convertAsn1TimeToEpochTime(not_after);
}

} // namespace osquery::tables

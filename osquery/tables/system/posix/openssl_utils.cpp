/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <openssl/x509v3.h>

#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

#include <osquery/core/core.h>
#include <osquery/tables/system/posix/openssl_utils.h>
#include <osquery/utils/conversions/join.h>

namespace osquery::tables {

std::string genSHA1ForCertificate(X509* cert) {
  const EVP_MD* fprint_type = EVP_sha1();
  unsigned char fprint[EVP_MAX_MD_SIZE] = {0};
  unsigned int fprint_size = 0;

  if (X509_digest(cert, fprint_type, fprint, &fprint_size)) {
    return genKIDProperty(fprint, fprint_size);
  }
  return "";
}

std::string genSerialForCertificate(X509* cert) {
  std::string hex;
  ASN1_INTEGER* serial = X509_get_serialNumber(cert);
  BIGNUM* bignumSerial = ASN1_INTEGER_to_BN(serial, nullptr);
  if (bignumSerial == nullptr) {
    return hex;
  }
  char* hexBytes = BN_bn2hex(bignumSerial);
  OPENSSL_free(bignumSerial);
  if (hexBytes == nullptr) {
    return hex;
  }
  hex = std::string(hexBytes);
  OPENSSL_free(hexBytes);
  return hex;
}

bool certificateIsCA(X509* cert) {
  int ca = X509_check_ca(cert);
  return (ca > 0);
}

bool certificateIsSelfSigned(X509* cert) {
  bool self_signed = (X509_check_issued(cert, cert) == X509_V_OK);
  return self_signed;
}

void genCommonName(X509* cert,
                   std::string& subject,
                   std::string& common_name,
                   std::string& issuer) {
  if (cert == nullptr) {
    return;
  }

  {
    X509_NAME* issuerName = X509_get_issuer_name(cert);
    if (issuerName != nullptr) {
      // Generate the string representation of the issuer.
      char* issuerBytes = X509_NAME_oneline(issuerName, nullptr, 0);
      if (issuerBytes != nullptr) {
        issuer = std::string(issuerBytes);
        OPENSSL_free(issuerBytes);
      }
    }
  }

  X509_NAME* subjectName = X509_get_subject_name(cert);
  if (subjectName == nullptr) {
    return;
  }

  {
    // Generate the string representation of the subject.
    char* subjectBytes = X509_NAME_oneline(subjectName, nullptr, 0);
    if (subjectBytes != nullptr) {
      subject = std::string(subjectBytes);
      OPENSSL_free(subjectBytes);
    }
  }

  int nid = OBJ_txt2nid("CN");

  int index = X509_NAME_get_index_by_NID(subjectName, nid, -1);
  if (index == -1) {
    return;
  }

  X509_NAME_ENTRY* commonNameEntry = X509_NAME_get_entry(subjectName, index);
  if (commonNameEntry == nullptr) {
    return;
  }

  ASN1_STRING* commonNameData = X509_NAME_ENTRY_get_data(commonNameEntry);

  const auto* data = ASN1_STRING_get0_data(commonNameData);

  common_name = std::string(reinterpret_cast<const char*>(data));
}

std::string genKIDProperty(const unsigned char* data, int len) {
  std::stringstream key_id;
  for (int i = 0; i < len; i++) {
    key_id << std::setw(2) << std::hex << std::setfill('0') << (int)data[i];
  }
  return key_id.str();
}

void genAlgorithmProperties(X509* cert,
                            std::string& key,
                            std::string& sig,
                            std::string& size) {
  ASN1_OBJECT* ppkalg;
  auto* pubkey = X509_get_X509_PUBKEY(cert);

  if (pubkey == nullptr) {
    return;
  }

  X509_PUBKEY_get0_param(&ppkalg, nullptr, nullptr, nullptr, pubkey);
  int nid = OBJ_obj2nid(ppkalg);

  if (nid != NID_undef) {
    key = std::string(OBJ_nid2ln(nid));

    // Get EVP public key, to determine public key size.
    EVP_PKEY* pkey = X509_get_pubkey(cert);
    if (pkey != nullptr) {
      if (nid == NID_rsaEncryption || nid == NID_dsa) {
        size_t key_size = 0;
        key_size = EVP_PKEY_size(pkey);
        size = std::to_string(key_size * 8);
      }

      // The EVP_size for EC keys returns the maximum buffer for storing the
      // key data, it does not indicate the size/strength of the curve.
      if (nid == NID_X9_62_id_ecPublicKey) {
        const EC_KEY* ec_pkey = EVP_PKEY_get0_EC_KEY(pkey);
        const EC_GROUP* ec_pkey_group = EC_KEY_get0_group(ec_pkey);
        int curve_nid = EC_GROUP_get_curve_name(ec_pkey_group);
        if (curve_nid != NID_undef) {
          size = std::string(OBJ_nid2ln(curve_nid));
        }
      }
    }
    EVP_PKEY_free(pkey);
  }

  nid = X509_get_signature_nid(cert);
  if (nid != NID_undef) {
    sig = std::string(OBJ_nid2ln(nid));
  }
}

time_t genEpoch(ASN1_TIME* time) {
  auto datetime = genHumanReadableDateTime(time);
  if (datetime.empty()) {
    return -1;
  }

  time_t epoch;
  struct tm tm;
  // b := abbr month, e := day with leading space instead of leading zero
  if (strptime(datetime.c_str(), "%b %e %H:%M:%S %Y %Z", &tm) == nullptr) {
    return -1;
  }

  // Don't set DST, since strptime() doesn't.
  // Let mktime() determine whether DST in effect
  tm.tm_isdst = -1;
  epoch = mktime(&tm);
  if (epoch == -1) {
    return -1;
  }
  return epoch;
}

// Key Usages (i.e. Digital Signature, CRL Sign etc) in ASN1/OpenSSL
// are represented as flags. These are then set by doing bitwise OR ops.
// genKeyUsage() reverses this to figure out which key usages are set.
std::string genKeyUsage(uint32_t flag) {
  if (flag == 0) {
    return "";
  }
  std::vector<std::string> results;
  for (const auto& key : kKeyUsageFlags) {
    if (flag & key.first) {
      results.push_back(key.second);
    }
  }
  return osquery::join(results, ", ");
}

std::string genHumanReadableDateTime(ASN1_TIME* time) {
  BIO* bio_stream = BIO_new(BIO_s_mem());
  if (bio_stream == nullptr) {
    return "";
  }

  // ANS1_TIME_print's format is: Mon DD HH:MM:SS YYYY GMT
  // e.g. Jan 1 00:00:00 1970 GMT (always GMT)
  auto buffer_size = 32;
  char buffer[32] = {0};
  if (!ASN1_TIME_print(bio_stream, time)) {
    BIO_free(bio_stream);
    return "";
  }

  // BIO_gets() returns amount of data successfully read or written
  // (if the return value is positive) or that no data was successfully
  // read or written if the result is 0 or -1.
  if (BIO_gets(bio_stream, buffer, buffer_size) <= 0) {
    BIO_free(bio_stream);
    return "";
  }

  BIO_free(bio_stream);
  return std::string(buffer);
}

} // namespace osquery::tables

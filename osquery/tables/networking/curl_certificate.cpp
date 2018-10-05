/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <iomanip>
#include <string>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <osquery/logger.h>
#include <osquery/tables.h>

namespace osquery {
namespace tables {

static void fillRow(Row& r, X509* cert) {
  std::vector<char> temp(256, 0x0);
  auto temp_size = static_cast<int>(temp.size());

  // set certificate subject information
  auto subject_name = X509_get_subject_name(cert);
  auto ret = X509_NAME_get_text_by_NID(
      subject_name, NID_commonName, temp.data(), temp_size);
  if (ret != -1) {
    r["common_name"] = std::string(temp.data());
  }

  ret = X509_NAME_get_text_by_NID(
      subject_name, NID_organizationName, temp.data(), temp_size);
  if (ret != -1) {
    r["organization"] = std::string(temp.data());
  }

  ret = X509_NAME_get_text_by_NID(
      subject_name, NID_organizationalUnitName, temp.data(), temp_size);
  if (ret != -1) {
    r["organization_unit"] = std::string(temp.data());
  }

  auto serial = X509_get_serialNumber(cert);
  auto bn = ASN1_INTEGER_to_BN(serial, nullptr);
  auto dec_str = BN_bn2hex(bn);
  if (dec_str != nullptr) {
    r["serial_number"] = std::string(dec_str);
    OPENSSL_free(dec_str);
  }

  BN_free(bn);

  // set certificate issuer information
  auto issuer_name = X509_get_issuer_name(cert);
  ret = X509_NAME_get_text_by_NID(
      issuer_name, NID_commonName, temp.data(), temp_size);
  if (ret != -1) {
    r["issuer_common_name"] = std::string(temp.data());
  }

  ret = X509_NAME_get_text_by_NID(
      issuer_name, NID_organizationName, temp.data(), temp_size);
  if (ret != -1) {
    r["issuer_organization"] = std::string(temp.data());
  }

  ret = X509_NAME_get_text_by_NID(
      issuer_name, NID_organizationalUnitName, temp.data(), temp_size);
  if (ret != -1) {
    r["issuer_organization_unit"] = std::string(temp.data());
  }

  // set period of validity
  auto valid_from = X509_get_notBefore(cert);
  auto valid_to = X509_get_notAfter(cert);
  auto b = BIO_new(BIO_s_mem());
  if (b != nullptr) {
    ASN1_TIME_print(b, valid_from);
    ret = BIO_gets(b, temp.data(), temp_size);
    if (ret != 0) {
      r["valid_from"] = std::string(temp.data());
    }

    ASN1_TIME_print(b, valid_to);
    ret = BIO_gets(b, temp.data(), temp_size);
    if (ret != 0) {
      r["valid_to"] = std::string(temp.data());
    }
    BIO_free(b);
  }

  // set SHA256 and SHA1 fingerprint
  std::vector<unsigned char> temp_c(256, 0x0);
  unsigned int len = 0;
  auto digest = const_cast<EVP_MD*>(EVP_sha256());
  ret = X509_digest(cert, digest, temp_c.data(), &len);

  std::stringstream ss;
  if (ret != 0) {
    for (size_t i = 0; i < len; i++) {
      ss << std::hex << std::setfill('0') << std::setw(2)
         << static_cast<unsigned>(temp_c[i]);
    }

    r["sha256_fingerprint"] = ss.str();
  }

  temp_c.clear();
  digest = const_cast<EVP_MD*>(EVP_sha1());
  ret = X509_digest(cert, digest, temp_c.data(), &len);

  if (ret != 0) {
    ss.str("");
    for (size_t i = 0; i < len; i++) {
      ss << std::hex << std::setfill('0') << std::setw(2)
         << static_cast<unsigned>(temp_c[i]);
    }

    r["sha1_fingerprint"] = ss.str();
  }
}

Status getTLSCertificate(std::string hostname, QueryData& results) {
  SSL_library_init();

  const auto method = TLSv1_method();
  if (method == nullptr) {
    return Status(1, "Failed to create OpenSSL method object");
  }

  auto delCTX = [](SSL_CTX* ctx) { SSL_CTX_free(ctx); };
  auto ctx =
      std::unique_ptr<SSL_CTX, decltype(delCTX)>(SSL_CTX_new(method), delCTX);
  if (ctx == nullptr) {
    return Status(1, "Failed to create OpenSSL CTX object");
  }

  auto delBIO = [](BIO* bio) { BIO_free_all(bio); };
  auto server = std::unique_ptr<BIO, decltype(delBIO)>(
      BIO_new_ssl_connect(ctx.get()), delBIO);
  if (server == nullptr) {
    return Status(1, "Failed to create OpenSSL BIO object");
  }

  std::string port = ":443";
  auto ext_hostname = hostname;
  auto conn_hostname = hostname;
  auto delim = hostname.find(":");
  if (delim == std::string::npos) {
    conn_hostname += ":443";
  } else {
    ext_hostname = hostname.substr(0, delim);
  }

  auto ret = BIO_set_conn_hostname(server.get(), conn_hostname.c_str());
  if (ret != 1) {
    return Status(1, "Failed to set OpenSSL hostname: " + std::to_string(ret));
  }

  SSL* ssl = nullptr;
  BIO_get_ssl(server.get(), &ssl);
  if (ssl == nullptr) {
    return Status(1, "Failed to retrieve OpenSSL object");
  }

  ret = SSL_set_tlsext_host_name(ssl, ext_hostname.c_str());
  if (ret != 1) {
    return Status(1,
                  "Failed to set OpenSSL server name: " + std::to_string(ret));
  }

  ret = BIO_do_connect(server.get());
  if (ret != 1) {
    return Status(1,
                  "Failed to establish TLS connection: " + std::to_string(ret));
  }

  ret = BIO_do_handshake(server.get());
  if (ret != 1) {
    return Status(1,
                  "Failed to complete TLS handshake: " + std::to_string(ret));
  }

  auto delX509 = [](X509* cert) { X509_free(cert); };
  auto cert = std::unique_ptr<X509, decltype(delX509)>(
      SSL_get_peer_certificate(ssl), delX509);
  if (cert == nullptr) {
    return Status(1, "No certificate");
  }

  Row r;
  r["hostname"] = hostname;
  fillRow(r, cert.get());
  results.push_back(r);
  return Status();
}

QueryData genTLSCertificate(QueryContext& context) {
  QueryData results;
  auto hostnames = context.constraints["hostname"].getAll(EQUALS);

  for (const auto& hostname : hostnames) {
    auto s = getTLSCertificate(hostname, results);
    if (!s.ok()) {
      LOG(INFO) << "Cannot get certificate for " << hostname << ": "
                << s.getMessage();
    }
  }

  return results;
}
}
}

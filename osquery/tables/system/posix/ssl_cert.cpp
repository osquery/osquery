/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

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
#define SHORT_STR 256
  char temp[SHORT_STR + 1];

  // set certificate subject information
  auto subject_name = X509_get_subject_name(cert);
  auto ret =
      X509_NAME_get_text_by_NID(subject_name, NID_commonName, temp, SHORT_STR);
  r["issued_common_name"] = ret == -1 ? "-1" : std::string(temp);

  ret = X509_NAME_get_text_by_NID(
      subject_name, NID_organizationName, temp, SHORT_STR);
  r["issued_organization"] = ret == -1 ? "-1" : std::string(temp);

  ret = X509_NAME_get_text_by_NID(
      subject_name, NID_organizationalUnitName, temp, SHORT_STR);
  r["issued_organization_unit"] = ret == -1 ? "-1" : std::string(temp);

  auto serial = X509_get_serialNumber(cert);
  auto bn = ASN1_INTEGER_to_BN(serial, NULL);
  auto dec_str = BN_bn2hex(bn);
  r["issued_serial_number"] = dec_str == NULL ? "-1" : std::string(dec_str);
  BN_free(bn);
  OPENSSL_free(dec_str);

  // set certificate issuer information
  auto issuer_name = X509_get_issuer_name(cert);
  ret = X509_NAME_get_text_by_NID(issuer_name, NID_commonName, temp, SHORT_STR);
  r["issuer_cn"] = ret == -1 ? "-1" : std::string(temp);

  ret = X509_NAME_get_text_by_NID(
      issuer_name, NID_organizationName, temp, SHORT_STR);
  r["issuer_organization"] = ret == -1 ? "-1" : std::string(temp);

  ret = X509_NAME_get_text_by_NID(
      issuer_name, NID_organizationalUnitName, temp, SHORT_STR);
  r["issuer_organization_unit"] = ret == -1 ? "-1" : std::string(temp);

  // set period of validity
  auto valid_from = X509_get_notBefore(cert);
  auto valid_to = X509_get_notAfter(cert);
  auto b = BIO_new(BIO_s_mem());

  ASN1_TIME_print(b, valid_from);
  ret = BIO_gets(b, temp, SHORT_STR);
  r["valid_from"] = ret == 0 ? "-1" : std::string(temp);

  ASN1_TIME_print(b, valid_to);
  ret = BIO_gets(b, temp, SHORT_STR);
  r["valid_to"] = ret == 0 ? "-1" : std::string(temp);
  BIO_free(b);

  // set sha 256 & 1 fingerprint
  unsigned char temp_c[SHORT_STR + 1];
  auto digest = const_cast<EVP_MD*>(EVP_sha256());
  unsigned len = SHORT_STR;
  ret = X509_digest(cert, digest, temp_c, &len);

  std::stringstream ss;
  for (unsigned i = 0; i < len; i++) {
    if (ret == 0)
      break;
    ss << std::uppercase << std::hex << std::setfill('0') << std::setw(2)
       << static_cast<unsigned>(temp_c[i]) << ':';
  }

  std::string hex_str = ss.str();
  r["sha256_fingerprint"] =
      ret == 0 ? "-1" : hex_str.substr(0, hex_str.size() - 1);

  memset(temp_c, 0, sizeof(temp_c));
  digest = const_cast<EVP_MD*>(EVP_sha1());
  ret = X509_digest(cert, digest, temp_c, &len);

  ss.str("");
  for (unsigned i = 0; i < len; i++) {
    if (ret == 0)
      break;
    ss << std::uppercase << std::hex << std::setfill('0') << std::setw(2)
       << static_cast<unsigned>(temp_c[i]) << ':';
  }

  hex_str = ss.str();
  r["sha1_fingerprint"] =
      ret == 0 ? "-1" : hex_str.substr(0, hex_str.size() - 1);

  return;
}

static void getSslCert(const std::string domain, QueryData& results) {
#define PORT ":443"
  SSL* ssl = NULL;

  (void)SSL_library_init();

  const auto method = SSLv23_method();
  if (!method)
    return;

  auto ctx = SSL_CTX_new(method);
  if (!ctx)
    return;

  auto server = BIO_new_ssl_connect(ctx);
  if (!server) {
    VLOG(1) << "Failed to create SSL bio";
    return;
  }

  if (BIO_set_conn_hostname(server, (domain + PORT).c_str()) != 1) {
    VLOG(1) << "Failed to set SSL domain and port " << domain << PORT;
    return;
  }

  BIO_get_ssl(server, &ssl);
  if (!ssl)
    return;

  if (SSL_set_tlsext_host_name(ssl, domain.c_str()) != 1)
    return;

  if (BIO_do_connect(server) != 1) {
    VLOG(1) << "Failed to establish SSL connection with " << domain;
    return;
  }

  if (BIO_do_handshake(server) != 1) {
    VLOG(1) << "Failed to complete SSL/TLS handshake with " << domain;
    return;
  }

  auto cert = SSL_get_peer_certificate(ssl);
  if (!cert) {
    VLOG(1) << "No certificate from " << domain;
    return;
  }
  Row r;
  r["domain"] = domain;
  fillRow(r, cert);
  results.push_back(r);

  if (cert)
    X509_free(cert);

  if (server)
    BIO_free_all(server);

  if (ctx)
    SSL_CTX_free(ctx);

  return;
}

QueryData genSslCert(QueryContext& context) {
  QueryData results;
  auto domains = context.constraints["domain"].getAll(EQUALS);

  for (const auto& domain : domains) {
    getSslCert(domain, results);
  }

  return results;
}
}
}

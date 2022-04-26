/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Include system.h before openssl, because windows.h should be included in
// specific environment. See osquery/utils/system/windows/system.h
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/scope_guard.h>
#include <osquery/utils/system/system.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/opensslv.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#ifdef WIN32
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#endif

#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>

#include <algorithm>
#include <iomanip>
#include <string>

namespace osquery {
namespace tables {

// set default to no read timeout
#define DEFAULT_READ_TIMEOUT 4

static std::string pem(X509* cert) {
  auto bio_out = BIO_new(BIO_s_mem());
  PEM_write_bio_X509(bio_out, cert);
  BUF_MEM* bio_buf = nullptr;
  BIO_get_mem_ptr(bio_out, &bio_buf);
  auto pem = std::string(bio_buf->data, bio_buf->length);
  BIO_free(bio_out);
  return pem;
}

static int certversion(X509* cert) {
  return X509_get_version(cert) + 1;
}

static std::string signature_algorithm(X509* cert) {
  auto sign_nid = X509_get_signature_nid(cert);
  if (sign_nid != NID_undef) {
    return OBJ_nid2sn(sign_nid);
  }
  return LN_undef;
}

static std::string signature(X509* cert) {
  ASN1_BIT_STRING* sign = nullptr;
  std::string signature;

  X509_get0_signature(
      const_cast<const ASN1_BIT_STRING**>(&sign), nullptr, cert);

  auto sig_nid = X509_get_signature_nid(cert);
  if (sig_nid != NID_undef) {
    auto n = sign->length;
    auto s = sign->data;
    auto bio_out = BIO_new(BIO_s_mem());
    for (auto i = 0; i < n; i++) {
      BIO_printf(bio_out, "%02x%s", s[i], ((i + 1) == n) ? "" : ":");
    }
    BUF_MEM* bio_buf = nullptr;
    BIO_get_mem_ptr(bio_out, &bio_buf);
    signature = std::string(bio_buf->data, bio_buf->length);
    BIO_free(bio_out);
  }
  return signature;
}

static std::string certificate_extensions(X509* cert, int nid) {
  auto extensions_stack = X509_get0_extensions(cert);

  if (extensions_stack == nullptr) {
    return {};
  }

  auto extension_idx = X509v3_get_ext_by_NID(extensions_stack, nid, -1);

  if (extension_idx < 0) {
    return {};
  }

  auto extension = X509v3_get_ext(extensions_stack, extension_idx);

  auto bio_out = BIO_new(BIO_s_mem());
  if (!X509V3_EXT_print(bio_out, extension, 0, 0)) {
    ASN1_STRING_print(bio_out, X509_EXTENSION_get_data(extension));
  }

  BUF_MEM* bio_buf = nullptr;
  BIO_get_mem_ptr(bio_out, &bio_buf);

  // remove the ending newline from the extension value
  auto length = bio_buf->length;
  if (bio_buf->data[length - 1] == '\n' || bio_buf->data[length - 1] == '\r') {
    bio_buf->data[length - 1] = '\0';
  }

  if (bio_buf->data[length] == '\n' || bio_buf->data[length] == '\r') {
    bio_buf->data[length] = '\0';
  }
  auto ident = std::string(bio_buf->data, bio_buf->length);

  // Replace the newline character with the comma
  std::replace(ident.begin(), ident.end(), '\n', ';');
  BIO_free(bio_out);

  return ident;
}

bool has_cert_expired(X509* cert) {
  return X509_cmp_current_time(X509_get_notAfter(cert)) <= 0;
}

static void fillRow(Row& r, X509* cert, int dump_certificate, int timeout) {
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

  std::fill(temp_c.begin(), temp_c.end(), 0x0);
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

  r["version"] = INTEGER(certversion(cert));
  r["signature_algorithm"] = signature_algorithm(cert);
  r["signature"] = signature(cert);

  // get the authority and subject key identifier
  // It will be same for self-signed certificate
  r["subject_key_identifier"] =
      certificate_extensions(cert, NID_subject_key_identifier);
  r["authority_key_identifier"] =
      certificate_extensions(cert, NID_authority_key_identifier);

  r["key_usage"] = certificate_extensions(cert, NID_key_usage);
  r["extended_key_usage"] = certificate_extensions(cert, NID_ext_key_usage);
  r["policies"] = certificate_extensions(cert, NID_certificate_policies);

  r["subject_alternative_names"] =
      certificate_extensions(cert, NID_subject_alt_name);
  r["issuer_alternative_names"] =
      certificate_extensions(cert, NID_issuer_alt_name);

  r["info_access"] = certificate_extensions(cert, NID_info_access);
  r["subject_info_access"] = certificate_extensions(cert, NID_sinfo_access);
  r["policy_mappings"] = certificate_extensions(cert, NID_policy_mappings);

  r["has_expired"] = has_cert_expired(cert) ? "1" : "0";

  r["basic_constraint"] = certificate_extensions(cert, NID_basic_constraints);
  r["name_constraints"] = certificate_extensions(cert, NID_name_constraints);
  r["policy_constraints"] =
      certificate_extensions(cert, NID_policy_constraints);

  // set the timeout flag
  r["timeout"] = INTEGER(timeout);

  // set the dump_certificate flag
  r["dump_certificate"] = INTEGER(dump_certificate);

  // check the dump_certificate flag and dump the certificate in PEM format
  if (dump_certificate) {
    r["pem"] = pem(cert);
  }
}

Status getTLSCertificate(const std::string& hostname,
                         QueryData& results,
                         int dump_certificate,
                         int timeout) {
  SSL_library_init();

  const auto method = TLS_method();

  if (method == nullptr) {
    return Status::failure("Failed to create OpenSSL method object");
  }

  auto delCTX = [](SSL_CTX* ctx) { SSL_CTX_free(ctx); };
  auto ctx =
      std::unique_ptr<SSL_CTX, decltype(delCTX)>(SSL_CTX_new(method), delCTX);
  if (ctx == nullptr) {
    return Status::failure("Failed to create OpenSSL CTX object");
  }

  std::string port = "443";
  auto connect_hostname = hostname;
  auto delim = hostname.find(":");
  if (delim + 1 == hostname.length()) {
    // if no port specified use default port
    connect_hostname = hostname.substr(0, delim);
  } else if (delim != std::string::npos) {
    port = hostname.substr(delim + 1, std::string::npos);
    connect_hostname = hostname.substr(0, delim);
  }

  int ret = 0;
#ifdef WIN32
  // Initialize Winsock
  WSADATA wsaData;
  ret = WSAStartup(MAKEWORD(2, 2), &wsaData);
  if (ret != 0) {
    return Status::failure("WSAStartup failed with error: " +
                           std::to_string(ret));
  }
  auto const wsa_guard = scope_guard::create([]() { WSACleanup(); });
#endif

  // connect up the socket first and then pass to BIO
  struct addrinfo hints, *addrinfo = nullptr, *current_addr = nullptr,
                         *preferred_addr = nullptr;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = PF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_NUMERICSERV | AI_ADDRCONFIG;

  ret = getaddrinfo(connect_hostname.c_str(), port.c_str(), &hints, &addrinfo);
  if (ret != 0 || addrinfo == nullptr) {
    return Status::failure("Unable to resolve hostname");
  }
  auto const ai_guard =
      scope_guard::create([addrinfo]() { freeaddrinfo(addrinfo); });

  current_addr = addrinfo;
  // take the first return as the default, but prefer IPv4 addrs
  preferred_addr = addrinfo;
  while (current_addr != nullptr) {
    if (current_addr->ai_family == AF_INET) {
      preferred_addr = current_addr;
      break;
    }
    current_addr = current_addr->ai_next;
  }

#ifdef WIN32
  SOCKET sock = 0;
#else
  int sock = 0;
#endif
  sock = socket(preferred_addr->ai_family,
                preferred_addr->ai_socktype,
                preferred_addr->ai_protocol);
  if (sock < 0) {
    return Status::failure("Unable to create socket");
  }

  if (timeout > 0) {
#ifdef WIN32
    DWORD tv = timeout * 1000;
#else
    struct timeval tv;
    tv.tv_sec = timeout;
    tv.tv_usec = 0;
#endif
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv) <
        0) {
      return Status::failure("Unable to set socket options");
    }
  }

  if (connect(sock, preferred_addr->ai_addr, (int)preferred_addr->ai_addrlen) <
      0) {
    return Status::failure("Failed to establish TCP connection");
  }
  auto const sock_guard = scope_guard::create([sock]() {
#ifdef WIN32
    closesocket(sock);
#else
    close(sock);
#endif
  });

  auto ssl = SSL_new(ctx.get());
  if (ssl == nullptr) {
    return Status::failure("Failed to create OpenSSL object");
  }
  auto const ssl_guard = scope_guard::create([ssl]() { SSL_free(ssl); });

  auto bio = BIO_new_socket((int)sock, BIO_NOCLOSE);
  if (bio == nullptr) {
    return Status::failure("Failed to create OpenSSL BIO object");
  }
  SSL_set_bio(ssl, bio, bio);

  ret = SSL_set_tlsext_host_name(ssl, connect_hostname.c_str());
  if (ret != 1) {
    return Status::failure("Failed to set OpenSSL server name: " +
                           std::to_string(ret));
  }

  // blocking mode
  SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
  auto cert_failure = Status::failure("No certificate");
  ret = SSL_connect(ssl);
  if (ret != 1) {
    cert_failure = Status::failure("Failed to begin TLS handshake: " +
                                   std::to_string(ret));
  }

  auto delX509 = [](X509* cert) { X509_free(cert); };
  auto cert = std::unique_ptr<X509, decltype(delX509)>(
      SSL_get_peer_certificate(ssl), delX509);
  if (cert == nullptr) {
    return cert_failure;
  }

  Row r;
  r["hostname"] = hostname;
  fillRow(r, cert.get(), dump_certificate, timeout);
  results.push_back(r);
  return Status::success();
}

QueryData genTLSCertificate(QueryContext& context) {
  QueryData results;
  auto dump_certificate = 0;
  auto timeout = DEFAULT_READ_TIMEOUT;
  auto hostnames = context.constraints["hostname"].getAll(EQUALS);

  if (context.hasConstraint("dump_certificate", EQUALS)) {
    dump_certificate = context.constraints["dump_certificate"].matches<int>(1);
  }

  if (context.hasConstraint("timeout", EQUALS)) {
    timeout =
        tryTo<int>(*(context.constraints["timeout"].getAll(EQUALS).begin()), 10)
            .takeOr(DEFAULT_READ_TIMEOUT);
    if (timeout < 0) {
      LOG(WARNING) << "Ignoring out of range timeout: " << timeout;
      timeout = DEFAULT_READ_TIMEOUT;
    }
  }

  for (const auto& hostname : hostnames) {
    auto s = getTLSCertificate(hostname, results, dump_certificate, timeout);
    if (!s.ok()) {
      LOG(INFO) << "Cannot get certificate for " << hostname << ": "
                << s.getMessage();
    }
  }

  return results;
}
} // namespace tables
} // namespace osquery

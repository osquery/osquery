/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <cstring>
#include <functional>
#include <string>
#include <utility>

#include <osquery/hashing/hashing.h>
#include <osquery/logger/logger.h>

#include <boost/asio/ip/address.hpp>
#include <boost/endian/buffers.hpp>
#include <sqlite3.h>

namespace errc = boost::system::errc;
namespace ip = boost::asio::ip;

namespace osquery {

static void hashSqliteValue(sqlite3_context* ctx,
                            int argc,
                            sqlite3_value** argv,
                            HashType ht) {
  if (argc == 0) {
    return;
  }

  if (SQLITE_NULL == sqlite3_value_type(argv[0])) {
    sqlite3_result_null(ctx);
    return;
  }

  // Parse and verify the split input parameters.
  const char* input =
      reinterpret_cast<const char*>(sqlite3_value_text(argv[0]));
  if (input == nullptr) {
    sqlite3_result_null(ctx);
    return;
  }

  auto result = hashFromBuffer(ht, input, strlen(input));
  sqlite3_result_text(
      ctx, result.c_str(), static_cast<int>(result.size()), SQLITE_TRANSIENT);
}

static void sqliteMD5Func(sqlite3_context* context,
                          int argc,
                          sqlite3_value** argv) {
  hashSqliteValue(context, argc, argv, HASH_TYPE_MD5);
}

static void sqliteSHA1Func(sqlite3_context* context,
                           int argc,
                           sqlite3_value** argv) {
  hashSqliteValue(context, argc, argv, HASH_TYPE_SHA1);
}

static void sqliteSHA256Func(sqlite3_context* context,
                             int argc,
                             sqlite3_value** argv) {
  hashSqliteValue(context, argc, argv, HASH_TYPE_SHA256);
}

static void sqliteCommunityIDv1(sqlite3_context* context,
                                int argc,
                                sqlite3_value** argv,
                                void (*errFunc)(sqlite3_context*,
                                                const char*)) {
  // Implemented as defined in https://github.com/corelight/community-id-spec

  const size_t saddr_idx = 0, daddr_idx = 1, sport_idx = 2, dport_idx = 3,
               proto_idx = 4, seed_idx = 5;

  boost::endian::big_int16_buf_t seed(0);
  if (argc == 6) {
    if (sqlite3_value_type(argv[seed_idx]) != SQLITE_INTEGER) {
      errFunc(context, "Community ID seed must be an integer");
      return;
    }
    const int64_t seed64 =
        static_cast<int64_t>(sqlite3_value_int64(argv[seed_idx]));
    if (seed64 < INT16_MIN || seed64 > INT16_MAX) {
      errFunc(context, "Community ID seed must fit in 2 bytes");
      return;
    }
    seed = seed64;
  }

  if (sqlite3_value_type(argv[saddr_idx]) != SQLITE_TEXT ||
      sqlite3_value_type(argv[daddr_idx]) != SQLITE_TEXT) {
    errFunc(context, "Community ID IPs must be strings");
    return;
  }
  const char* saddr_str =
      reinterpret_cast<const char*>(sqlite3_value_text(argv[saddr_idx]));
  const char* daddr_str =
      reinterpret_cast<const char*>(sqlite3_value_text(argv[daddr_idx]));

  boost::system::error_code ec;
  ip::address saddr = ip::make_address(saddr_str, ec);
  if (ec.value() != errc::success) {
    errFunc(context, "Community ID saddr cannot be parsed as IP");
    return;
  }
  ip::address daddr = ip::make_address(daddr_str, ec);
  if (ec.value() != errc::success) {
    errFunc(context, "Community ID daddr cannot be parsed as IP");
    return;
  }

  if (sqlite3_value_type(argv[sport_idx]) != SQLITE_INTEGER ||
      sqlite3_value_type(argv[dport_idx]) != SQLITE_INTEGER) {
    errFunc(context, "Community ID ports must be integers");
    return;
  }
  const int64_t sport64 =
      static_cast<int64_t>(sqlite3_value_int64(argv[sport_idx]));
  const int64_t dport64 =
      static_cast<int64_t>(sqlite3_value_int64(argv[dport_idx]));
  if (sport64 < 0 || sport64 > UINT16_MAX || dport64 < 0 ||
      dport64 > UINT16_MAX) {
    errFunc(context, "Community ID ports must fit in 2 bytes");
    return;
  }
  boost::endian::big_uint16_buf_t sport(sport64);
  boost::endian::big_uint16_buf_t dport(dport64);

  if (sqlite3_value_type(argv[proto_idx]) != SQLITE_INTEGER) {
    errFunc(context, "Community ID protocol must be an integer");
    return;
  }
  const int64_t proto64 =
      static_cast<int64_t>(sqlite3_value_int64(argv[proto_idx]));
  if (proto64 < 0 || proto64 > UINT8_MAX) {
    errFunc(context, "Community ID protocol must fit in 1 byte");
    return;
  }
  uint8_t proto = proto64;

  // Ensure ordering
  if (!(saddr < daddr || (saddr == daddr && sport64 < dport64))) {
    std::swap(saddr, daddr);
    std::swap(sport, dport);
  }

  // seed . saddr . daddr . proto . 0 . sport . dport
  std::array<char, 2> buffer;
  std::memcpy(buffer.data(), seed.data(), buffer.size());

  std::stringstream bytes;
  bytes.write(buffer.data(), buffer.size());
  if (saddr.is_v4()) {
    bytes.write(reinterpret_cast<const char*>(saddr.to_v4().to_bytes().data()),
                4);
  } else {
    bytes.write(reinterpret_cast<const char*>(saddr.to_v6().to_bytes().data()),
                16);
  }
  if (daddr.is_v4()) {
    bytes.write(reinterpret_cast<const char*>(daddr.to_v4().to_bytes().data()),
                4);
  } else {
    bytes.write(reinterpret_cast<const char*>(daddr.to_v6().to_bytes().data()),
                16);
  }
  bytes.write(reinterpret_cast<const char*>(&proto), 1);
  bytes.put(0);

  std::memcpy(buffer.data(), sport.data(), buffer.size());
  bytes.write(buffer.data(), buffer.size());

  std::memcpy(buffer.data(), dport.data(), buffer.size());
  bytes.write(buffer.data(), buffer.size());

  std::string res = bytes.str();

  Hash hash(HASH_TYPE_SHA1, HASH_ENCODING_TYPE_BASE64);
  hash.update(res.c_str(), res.size());
  auto result = "1:" + hash.digest();

  sqlite3_result_text(context,
                      result.c_str(),
                      static_cast<int>(result.size()),
                      SQLITE_TRANSIENT);
}

static void sqliteCommunityIDv1Error(sqlite3_context* context,
                                     int argc,
                                     sqlite3_value** argv) {
  auto handleError = [](sqlite3_context* context, const char* errMsg) {
    sqlite3_result_error(context, errMsg, -1);
  };
  sqliteCommunityIDv1(context, argc, argv, handleError);
}

static void sqliteCommunityIDv1Null(sqlite3_context* context,
                                    int argc,
                                    sqlite3_value** argv) {
  auto handleError = [](sqlite3_context* context, const char* errMsg) {
    sqlite3_result_null(context);
    LOG(WARNING) << errMsg;
  };
  sqliteCommunityIDv1(context, argc, argv, handleError);
}

void registerHashingExtensions(sqlite3* db) {
  sqlite3_create_function(db,
                          "md5",
                          1,
                          SQLITE_UTF8 | SQLITE_DETERMINISTIC,
                          nullptr,
                          sqliteMD5Func,
                          nullptr,
                          nullptr);
  sqlite3_create_function(db,
                          "sha1",
                          1,
                          SQLITE_UTF8 | SQLITE_DETERMINISTIC,
                          nullptr,
                          sqliteSHA1Func,
                          nullptr,
                          nullptr);
  sqlite3_create_function(db,
                          "sha256",
                          1,
                          SQLITE_UTF8 | SQLITE_DETERMINISTIC,
                          nullptr,
                          sqliteSHA256Func,
                          nullptr,
                          nullptr);
  sqlite3_create_function(db,
                          "community_id_v1",
                          5,
                          SQLITE_UTF8 | SQLITE_DETERMINISTIC,
                          nullptr,
                          sqliteCommunityIDv1Null,
                          nullptr,
                          nullptr);
  sqlite3_create_function(db,
                          "community_id_v1",
                          6, // with seed
                          SQLITE_UTF8 | SQLITE_DETERMINISTIC,
                          nullptr,
                          sqliteCommunityIDv1Null,
                          nullptr,
                          nullptr);
  sqlite3_create_function(db,
                          "community_id_v1_strict",
                          5,
                          SQLITE_UTF8 | SQLITE_DETERMINISTIC,
                          nullptr,
                          sqliteCommunityIDv1Error,
                          nullptr,
                          nullptr);
  sqlite3_create_function(db,
                          "community_id_v1_strict",
                          6, // with seed
                          SQLITE_UTF8 | SQLITE_DETERMINISTIC,
                          nullptr,
                          sqliteCommunityIDv1Error,
                          nullptr,
                          nullptr);
}
} // namespace osquery

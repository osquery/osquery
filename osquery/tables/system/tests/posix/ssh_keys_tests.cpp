/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <fstream>

#include <boost/filesystem.hpp>

#include <gtest/gtest.h>

#include <boost/filesystem.hpp>
#include <gtest/gtest.h>
#include <osquery/sql/sql.h>
#include <osquery/tables/system/posix/ssh_keys.h>
#include <osquery/utils/scope_guard.h>
#include <osquery/worker/logging/glog/glog_logger.h>

namespace fs = boost::filesystem;

// ssh-keygen -t rsa -b 1024 -N ''
const std::string kRsaUnencrypted = R"(-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQC9MV4sOpwCeYi/Cp5jrd/CFWRAFPXAj4431v0fjzhjCEPqggEO
Aofpyqjh+mM5ToQLGo0baPiF3dNA9o0MHZFyfAfD/Jok0G1F7ByqwpS+/S9SQ2kG
23PjD+8DZJA8LF496t4lr6SBPguCquw5MyEhv2WeOTrYYPvohQa1iA9I8QIDAQAB
AoGAXuF6TA4cnXUb6ktGAdF6TRhzTVv1n1ufREvSZ9hou+myPdJy+vaz+MDFD4eF
6YCB4huvtpZfRKtpvcOoGvJdNUJKLjv3LoHQWzhWUiP9O3XbLG3b2Hr/RKI4yQFQ
bvEK4tvDvvimAnp4K2wNWHM0Kg1pL0N0oVOfjKu1qxHPtd0CQQDynOZaKc+2xjsZ
CUjAt7jVkCLjSjRNmOjHUXCehcFc44n7SuQwKdvL6PyYqHUcxxsLmPi9GFhl3FKU
2dmC496rAkEAx6HeC9P9E73jFmw2WQLf+vhzwymrfGL90uXIeE+4vqAVOQc8UrFS
5wTTQh83WhplZ2dCjV9hVFLXtMoc1hRG0wJBAOrZluKQttFm8q45noNvVSzmad87
ZYX4Dt1iqHHLaHJSkK8AwAMfgfTRhDMCXtuMoVGIsr/ZYTi5HfeZKkTZ8CECQDbJ
g6j3WuNKH8KNnDS9hz7XZN3Q19FhUYvJqETsjCU0xd5K0BFZvQjN2DSzYHuH9wBz
5F3sKUf9HFnvhg5yriUCQGYtoBvMGPcAzaZQ6rtmfXxUBSHfFU3wX+1Z4i1Gonb9
tLRdtCx5SLsaVpdWslTCD0izLC4YEgYOrlWDrPSbiQU=
-----END RSA PRIVATE KEY-----
)";

// ssh-keygen -t rsa -b 1024 -N 'osquery'
const std::string kRsaEncrypted =
    R"(-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,5F2D5A76540C4C9366061E04B8AD5382

yYYTbNWNwzRaxGRbwqoHJR5ery8ZWJF4SwuYgrio+fucfYpmTTk0s0CHAqKHRZXe
z8mygti52juDYRJmpG33pElm3LfkmhPO86D5DeVYSsLNKu61PgsZqURR0WhAdqts
oniK/rkBXCB+Vk7DcENCPIiMoxaoyK4332qlbtz4X8e47F3ga0AmQm+etV5eO++S
w34lyylOTPHg93Ao3Jc7Jso5151vGLr4CjoeHfmQPAObjd4hteiFhRfsgRQZqAIv
O+HLAoqMmx0mFkfA3wlo9SDUmZuWcgxOdSBQEhLJ+lNNo9tmY3ZdvBq/qQL4htme
C/9EpSuwRJoMKdW55sgVuRkif9+yvnqbkxJZw1ONezOr+03r66YYrks98nBgCKTY
Pc7NOFFTvmjX0VV6bL+v2Yk/UaqZ6qnMH//dEVMPXIXMKpDLvmH+2dHn39cuAHWn
dNEKdB21EzvepjbtC/+MgQFb+yBYZx6FOzaJQZkUmDin3VUwGoVL29dvSFZ4do4u
AJOziYrsUOnZORUNkCHPqnSflIzudgLPVUAeBNC7/0VwnuFucJvIdAgYatAcvdYp
M4JInkgDpQYkHh1ZN30eIclguspLs+dHFfJco5VZg6OhTm+dpsI837229J+CZThV
3gMbj9QItqoB+RdYtAaCxC6/8MDG7rUOnaNyXv+Z7F3PJ37lficxaHBHoyA0CYli
RPp1ENrwmNqR2Hfl4JQCbACh7syyC0F9qq9BWVzeOwY+WSTK1+Tdqp+esi749VW0
OmavH/dSTJTM6bQuzYBNw97xGhUzkvPotkLm/LY4EMi4hf9RJzXwzYcbSy8N+N28
-----END RSA PRIVATE KEY-----
)";

// ssh-keygen -t ed25519 -b 1024 -N ''
const std::string kEd25519Unencrypted = R"(-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAxBdSIEpSo2GCI+XFNJVMMMtMFqCM2PtxU15kJod968gAAAKAl+A8pJfgP
KQAAAAtzc2gtZWQyNTUxOQAAACAxBdSIEpSo2GCI+XFNJVMMMtMFqCM2PtxU15kJod968g
AAAECElvYf6Uw04m5FzC6pK2F9m654mgKLsTi7mOHCuSzN/DEF1IgSlKjYYIj5cU0lUwwy
0wWoIzY+3FTXmQmh33ryAAAAGnJvYmJpZUBIZXBoYWVzdHVzLUlJLmxvY2FsAQID
-----END OPENSSH PRIVATE KEY-----
)";

// ssh-keygen -t ed25519 -b 1024 -N 'osquery'
const std::string kEd25519Encrypted = R"(-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABBtHgT9BK
xU2YnYX1Kmhd2+AAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAINuzCGrt5ycXx5zy
Qmg9LgQK0AfqJjrMc5hY2okjK7GxAAAAoPtS99mcHbCChhVBtyrPiZp7lteeZT5fj2kj19
kgjZXM0IjDqUY3yHeBdSOJq6xV+5jPYd8GzWxCjdWPlRQpaJbqQYeZIMes+xFE+dQYBcIb
HViYhoiqtoA7rjzFZVReI2tgytE0cyJHIPAqpUaGFiMrNrGoZqwvNL3eHfY654UfYqGbLN
lr3nvK/353Djovxgm6WxHe82aPpQvBlDbEiR0=
-----END OPENSSH PRIVATE KEY-----
)";

// ssh-keygen -t dsa -b 1024 -N ''
const std::string kDsaUnencrypted = R"(-----BEGIN DSA PRIVATE KEY-----
MIIBugIBAAKBgQCfH5N5h6a/9t9V0RnHUjsdTTE7vi6C4uMMbDRdnX1U/Or6eoY6
3qFKDOto8UmSeVNgmYf7yUfcO3P89m2BckzHPJbabHRm5cHjsKl8h1+MFHoXzNBY
QnUzZJRokGrnHc2p8W6Yz3ABAJDy/VarTIuJOA9mhLya7wVgwLORk5dAcQIVAKdD
GwYrdxW3TldRSgQemq91RnIvAoGAftjV5PtN0bCS9BXBzYnU80pNLLDSXZxa0aIj
b1Lafi4yD3zNPHexIZcKJff+9wi+eeKKRBAmcO9xCCGRrLsFqvK7BYLX6mf+B/d5
cYOlyhJ6vb8tmmfwq3m1/fDaYj+Jcr+gMj6fCMcuAHLT+Qbd9+vLNOFbjGb/HvrI
iA2sMEcCgYAzoSqFkgLS2NUVlaOTG3sbHEYQgMAYVi5qmgFIB6Co6qO8cSHFziuc
U7PU/WINSt/m9QpAl5sl5gJvDO7s+5XbXbDmdvyjvBuUo1MUm2YsOATM6dLX1fl2
b9uYdciS8xDZGUe7BvFR5iZW2P0WLU+j2nm1lZ6yHDXnSawFrGd/8wIUfv/G+GZQ
UQ2bWX3iqGz7GKbKvVI=
-----END DSA PRIVATE KEY-----
)";

// ssh-keygen -t dsa -b 1024 -N 'osquery'
const std::string kDsaEncrypted =
    R"(-----BEGIN DSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,4776535AE68A52C8C65C3EF8375C71A3

priHoiSJGZSp8Qg1ncE8UvZp2HX3IvtLvsycVlr2H7yeuKIbXDZN4zF7wV3wN19t
h27UTXZ4AYnPlIHAWOUt1dPF18tY1naCEsJQsm/+wNWN2Oq3ZbKEurB/ZpejsuS7
JJ9nZDRqmHkc9GQsIFZ3DFo9VTC6SjGoTU/yipRGn5T8JAme9I1D9NrpmfSfHiwS
JGyjUn2QpZui7hCh5MYWv/OiR+3Qaap5m7wvrPshkTCG6NilhfCg2D/vmauthgYQ
QSYv7W3odFWfy0dpRFBmeI4Rfbm1Grp4+3iR1S+BQKSusiucoufPHD6tRA9Kqv+e
S9EzAe9igP1E7CuYmUilloB9uu/bldljV5rsK84gQCysB7aFyjbSDA3c0n9Qtn1s
MjWRb/GTHjMXz+kRveUAErIC+G27QJMB/fq/q3k8Hc5B5H8djXg9Pg02MnRItbjL
sOPSbcdl7/4UF3erCwfqDVTc60wTZwNyQ0hMWNcIHwFTdP8dTBtJhuTpJxoCldNa
jN1jCIAhAAttxOoNVSNEzqko7KrdIte+lSwhPb4nnsRCt3GVx8NNFHEKJjM17xx6
BIQxZ7GBy1EHTqNWP7UhZg==
-----END DSA PRIVATE KEY-----
)";

namespace osquery {
namespace tables {

class SshKeysTests : public testing::Test {
 protected:
  void SetUp() override {
    directory = fs::temp_directory_path() /
                fs::unique_path("osquery.ssh_keys_impl_tests.%%%%-%%%%");

    ASSERT_TRUE(fs::create_directories(directory));

    ssh_directory = directory / fs::path(kSSHUserKeysDir);

    ASSERT_TRUE(fs::create_directories(ssh_directory));
  }
  void TearDown() override {
    fs::remove_all(directory);
  }
  fs::path directory;
  fs::path ssh_directory;
};

TEST_F(SshKeysTests, invalid_key) {
  auto results = QueryData{};

  {
    auto filepath = ssh_directory / fs::path("invalid");
    auto fout =
        std::ofstream(filepath.native(), std::ios::out | std::ios::binary);
    fout << "this is an invalid key" << '\n';
  }
  auto const uid = std::to_string(geteuid());
  GLOGLogger logger;
  genSSHkeyForHosts(
      uid, std::to_string(getegid()), directory.native(), results, logger);
  ASSERT_EQ(results.size(), 0u);
}

TEST_F(SshKeysTests, rsa_key_unencrypted) {
  auto results = QueryData{};

  auto filepath = ssh_directory / fs::path("rsa_unencrypted");
  {
    auto fout =
        std::ofstream(filepath.native(), std::ios::out | std::ios::binary);
    fout << kRsaUnencrypted;
  }
  auto const uid = std::to_string(geteuid());
  GLOGLogger logger;
  genSSHkeyForHosts(
      uid, std::to_string(getegid()), directory.native(), results, logger);
  ASSERT_EQ(results.size(), 1u);

  const auto& row = results[0];
  EXPECT_EQ(row.at("uid"), uid);
  EXPECT_EQ(row.at("path"), fs::canonical(filepath).native());
  EXPECT_EQ(row.at("encrypted"), "0");
  EXPECT_EQ(row.at("key_type"), "rsa");
}

TEST_F(SshKeysTests, rsa_key_encrypted) {
  auto results = QueryData{};

  auto filepath = ssh_directory / fs::path("rsa_encrypted");
  {
    auto fout =
        std::ofstream(filepath.native(), std::ios::out | std::ios::binary);
    fout << kRsaEncrypted;
  }
  auto const uid = std::to_string(geteuid());
  GLOGLogger logger;
  genSSHkeyForHosts(
      uid, std::to_string(getegid()), directory.native(), results, logger);
  ASSERT_EQ(results.size(), 1u);

  const auto& row = results[0];
  EXPECT_EQ(row.at("uid"), uid);
  EXPECT_EQ(row.at("path"), fs::canonical(filepath).native());
  EXPECT_EQ(row.at("encrypted"), "1");
  EXPECT_EQ(row.at("key_type"), "");
}

TEST_F(SshKeysTests, dsa_unencrypted) {
  auto results = QueryData{};

  auto filepath = ssh_directory / fs::path("dsa_unencrypted");
  {
    auto fout =
        std::ofstream(filepath.native(), std::ios::out | std::ios::binary);
    fout << kDsaUnencrypted;
  }
  auto const uid = std::to_string(geteuid());
  GLOGLogger logger;
  genSSHkeyForHosts(
      uid, std::to_string(getegid()), directory.native(), results, logger);
  ASSERT_EQ(results.size(), 1u);

  const auto& row = results[0];
  EXPECT_EQ(row.at("uid"), uid);
  EXPECT_EQ(row.at("path"), fs::canonical(filepath).native());
  EXPECT_EQ(row.at("encrypted"), "0");
  EXPECT_EQ(row.at("key_type"), "dsa");
}

TEST_F(SshKeysTests, dsa_encrypted) {
  auto results = QueryData{};

  auto filepath = ssh_directory / fs::path("dsa_encrypted");
  {
    auto fout =
        std::ofstream(filepath.native(), std::ios::out | std::ios::binary);
    fout << kDsaEncrypted;
  }
  auto const uid = std::to_string(geteuid());
  GLOGLogger logger;
  genSSHkeyForHosts(
      uid, std::to_string(getegid()), directory.native(), results, logger);
  ASSERT_EQ(results.size(), 1u);

  const auto& row = results[0];
  EXPECT_EQ(row.at("uid"), uid);
  EXPECT_EQ(row.at("path"), fs::canonical(filepath).native());
  EXPECT_EQ(row.at("encrypted"), "1");
  EXPECT_EQ(row.at("key_type"), "");
}

TEST_F(SshKeysTests, ed25519_unencrypted) {
  auto results = QueryData{};

  auto filepath = ssh_directory / fs::path("ed25519_unencrypted");
  {
    auto fout =
        std::ofstream(filepath.native(), std::ios::out | std::ios::binary);
    fout << kEd25519Unencrypted;
  }
  auto const uid = std::to_string(geteuid());
  GLOGLogger logger;
  genSSHkeyForHosts(
      uid, std::to_string(getegid()), directory.native(), results, logger);
  ASSERT_EQ(results.size(), 1u);

  const auto& row = results[0];
  EXPECT_EQ(row.at("uid"), uid);
  EXPECT_EQ(row.at("path"), fs::canonical(filepath).native());
  EXPECT_EQ(row.at("encrypted"), "0");
  EXPECT_EQ(row.at("key_type"), "");
}

TEST_F(SshKeysTests, ed25519_encrypted) {
  auto results = QueryData{};

  auto filepath = ssh_directory / fs::path("ed25519_encrypted");
  {
    auto fout =
        std::ofstream(filepath.native(), std::ios::out | std::ios::binary);
    fout << kEd25519Encrypted;
  }
  auto const uid = std::to_string(geteuid());
  GLOGLogger logger;
  genSSHkeyForHosts(
      uid, std::to_string(getegid()), directory.native(), results, logger);
  ASSERT_EQ(results.size(), 1u);

  const auto& row = results[0];
  EXPECT_EQ(row.at("uid"), uid);
  EXPECT_EQ(row.at("path"), fs::canonical(filepath).native());
  EXPECT_EQ(row.at("encrypted"), "1");
  EXPECT_EQ(row.at("key_type"), "");
}

} // namespace tables
} // namespace osquery

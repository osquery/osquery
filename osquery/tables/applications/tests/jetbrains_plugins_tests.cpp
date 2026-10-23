/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <iterator>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <boost/filesystem.hpp>

#include <osquery/tables/applications/jetbrains_plugins.h>
#include <osquery/tests/test_util.h>

#define LIBARCHIVE_STATIC
#include <archive.h>
#include <archive_entry.h>

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

namespace {

const std::vector<char> kZipCentralHeaderSignature = {'P', 'K', 0x01, 0x02};

std::string makePluginXml(std::size_t size) {
  const std::string prefix =
      "<idea-plugin><name>H3</name><vendor>H3</vendor><version>1</version>"
      "<!--";
  const std::string suffix = "--></idea-plugin>";

  if (size < prefix.size() + suffix.size()) {
    return {};
  }

  return prefix + std::string(size - prefix.size() - suffix.size(), 'A') +
         suffix;
}

std::vector<char>::iterator findSignature(std::vector<char>& archive_data,
                                          const std::vector<char>& signature) {
  return std::search(archive_data.begin(),
                     archive_data.end(),
                     signature.begin(),
                     signature.end());
}

void writeArchiveData(const fs::path& path,
                      const std::vector<char>& archive_data) {
  std::ofstream stream(path.string(), std::ios::binary | std::ios::trunc);
  ASSERT_TRUE(stream.is_open());
  stream.write(archive_data.data(),
               static_cast<std::streamsize>(archive_data.size()));
  ASSERT_TRUE(stream.good());
}

std::vector<char> readArchiveData(const fs::path& path) {
  std::ifstream stream(path.string(), std::ios::binary);
  EXPECT_TRUE(stream.is_open());
  return {std::istreambuf_iterator<char>(stream),
          std::istreambuf_iterator<char>()};
}

void setLittleEndian32(std::vector<char>& data,
                       std::size_t offset,
                       std::uint32_t value) {
  ASSERT_LE(offset + sizeof(value), data.size());
  for (std::size_t index = 0; index < sizeof(value); ++index) {
    data[offset + index] = static_cast<char>((value >> (index * 8U)) & 0xFFU);
  }
}

} // namespace

class JetbrainsPluginsTest : public ::testing::Test {
 protected:
  void SetUp() override {
    root_ = fs::temp_directory_path() /
            fs::unique_path("osquery-jetbrains-plugins-%%%%%%");
    fs::create_directories(root_);
  }

  void TearDown() override {
    fs::remove_all(root_);
  }

  void createPluginArchive(
      const fs::path& path,
      const std::string& content,
      std::optional<std::int64_t> declared_size = std::nullopt) {
    std::unique_ptr<struct archive, decltype(&archive_write_free)>
        archive_writer(archive_write_new(), archive_write_free);
    ASSERT_NE(archive_writer, nullptr);
    ASSERT_EQ(archive_write_set_format_zip(archive_writer.get()), ARCHIVE_OK);
    ASSERT_EQ(archive_write_open_filename(archive_writer.get(),
                                          path.string().c_str()),
              ARCHIVE_OK);

    std::unique_ptr<struct archive_entry, decltype(&archive_entry_free)> entry(
        archive_entry_new(), archive_entry_free);
    ASSERT_NE(entry, nullptr);
    archive_entry_set_pathname(entry.get(), "META-INF/plugin.xml");
    archive_entry_set_filetype(entry.get(), AE_IFREG);
    archive_entry_set_perm(entry.get(), 0644);
    if (declared_size.has_value()) {
      archive_entry_set_size(entry.get(), declared_size.value());
    }

    ASSERT_EQ(archive_write_header(archive_writer.get(), entry.get()),
              ARCHIVE_OK);
    ASSERT_EQ(archive_write_data(
                  archive_writer.get(), content.data(), content.size()),
              static_cast<la_ssize_t>(content.size()));
    ASSERT_EQ(archive_write_close(archive_writer.get()), ARCHIVE_OK);
  }

  void createUnknownSizePluginArchive(const fs::path& path) {
    std::unique_ptr<struct archive, decltype(&archive_write_free)>
        archive_writer(archive_write_new(), archive_write_free);
    ASSERT_NE(archive_writer, nullptr);
    ASSERT_EQ(archive_write_set_format_iso9660(archive_writer.get()),
              ARCHIVE_OK);
    ASSERT_EQ(archive_write_open_filename(archive_writer.get(),
                                          path.string().c_str()),
              ARCHIVE_OK);

    std::unique_ptr<struct archive_entry, decltype(&archive_entry_free)> entry(
        archive_entry_new(), archive_entry_free);
    ASSERT_NE(entry, nullptr);
    archive_entry_set_pathname(entry.get(), "payload");
    archive_entry_set_filetype(entry.get(), AE_IFREG);
    archive_entry_set_perm(entry.get(), 0644);
    archive_entry_set_size(entry.get(), 1);
    archive_entry_set_nlink(entry.get(), 2);
    ASSERT_EQ(archive_write_header(archive_writer.get(), entry.get()),
              ARCHIVE_OK);
    ASSERT_EQ(archive_write_data(archive_writer.get(), "x", 1), 1);

    archive_entry_clear(entry.get());
    archive_entry_set_pathname(entry.get(), "META-INF/plugin.xml");
    archive_entry_set_filetype(entry.get(), AE_IFREG);
    archive_entry_set_perm(entry.get(), 0644);
    archive_entry_set_hardlink(entry.get(), "payload");
    archive_entry_set_nlink(entry.get(), 2);
    ASSERT_EQ(archive_write_header(archive_writer.get(), entry.get()),
              ARCHIVE_OK);
    ASSERT_EQ(archive_write_close(archive_writer.get()), ARCHIVE_OK);
  }

  fs::path root_;
};

TEST_F(JetbrainsPluginsTest, test_extracts_normal_plugin_xml) {
  const auto archive_path = root_ / "normal.jar";
  createPluginArchive(archive_path, makePluginXml(1024), 1024);

  const auto attributes = attributesFromJar(archive_path.string());
  ASSERT_NE(attributes, nullptr);
  EXPECT_EQ(attributes->name, "H3");
  EXPECT_EQ(attributes->vendor, "H3");
  EXPECT_EQ(attributes->version, "1");
}

TEST_F(JetbrainsPluginsTest, test_accepts_plugin_xml_at_size_limit) {
  const auto archive_path = root_ / "boundary.jar";
  const auto content = makePluginXml(kMaxJetBrainsPluginXmlSize);
  createPluginArchive(archive_path, content, kMaxJetBrainsPluginXmlSize);

  EXPECT_NE(attributesFromJar(archive_path.string()), nullptr);
}

TEST_F(JetbrainsPluginsTest, test_rejects_declared_oversized_plugin_xml) {
  const auto archive_path = root_ / "declared-oversized.jar";
  const auto content = makePluginXml(kMaxJetBrainsPluginXmlSize + 1U);
  createPluginArchive(archive_path, content, kMaxJetBrainsPluginXmlSize + 1U);

  EXPECT_EQ(attributesFromJar(archive_path.string()), nullptr);
}

TEST_F(JetbrainsPluginsTest, test_handles_unknown_size_plugin_xml) {
  const auto archive_path = root_ / "unknown-size.jar";
  createUnknownSizePluginArchive(archive_path);

  std::unique_ptr<struct archive, decltype(&archive_read_free)> archive_reader(
      archive_read_new(), archive_read_free);
  ASSERT_NE(archive_reader, nullptr);
  ASSERT_EQ(archive_read_support_format_all(archive_reader.get()), ARCHIVE_OK);
  ASSERT_EQ(archive_read_support_filter_all(archive_reader.get()), ARCHIVE_OK);
  ASSERT_EQ(archive_read_open_filename(
                archive_reader.get(), archive_path.string().c_str(), 10240),
            ARCHIVE_OK);

  struct archive_entry* entry{nullptr};
  while (archive_read_next_header(archive_reader.get(), &entry) == ARCHIVE_OK &&
         std::string(archive_entry_pathname(entry)) != "META-INF/plugin.xml") {
    archive_read_data_skip(archive_reader.get());
  }
  ASSERT_NE(entry, nullptr);
  ASSERT_STREQ(archive_entry_pathname(entry), "META-INF/plugin.xml");
  ASSERT_EQ(archive_entry_size_is_set(entry), 0);

  EXPECT_EQ(attributesFromJar(archive_path.string()), nullptr);
}

TEST_F(JetbrainsPluginsTest, test_rejects_underreported_plugin_xml_size) {
  const auto archive_path = root_ / "underreported-size.jar";
  const auto content = makePluginXml(kMaxJetBrainsPluginXmlSize + 1U);
  createPluginArchive(archive_path, content, kMaxJetBrainsPluginXmlSize + 1U);

  auto archive_data = readArchiveData(archive_path);
  const auto central_header =
      findSignature(archive_data, kZipCentralHeaderSignature);
  ASSERT_NE(central_header, archive_data.end());
  setLittleEndian32(
      archive_data,
      static_cast<std::size_t>(central_header - archive_data.begin()) + 24U,
      1U);
  writeArchiveData(archive_path, archive_data);

  EXPECT_EQ(attributesFromJar(archive_path.string()), nullptr);
}

TEST_F(JetbrainsPluginsTest, test_discards_partial_malformed_plugin_xml) {
  const auto archive_path = root_ / "malformed.jar";
  createPluginArchive(archive_path, makePluginXml(1024 * 1024), 1024 * 1024);

  auto archive_data = readArchiveData(archive_path);
  const auto central_header =
      findSignature(archive_data, kZipCentralHeaderSignature);
  ASSERT_NE(central_header, archive_data.end());
  ASSERT_GT(central_header - archive_data.begin(), 16);
  archive_data.erase(central_header - 8, archive_data.end());
  writeArchiveData(archive_path, archive_data);

  EXPECT_EQ(attributesFromJar(archive_path.string()), nullptr);
}

TEST_F(JetbrainsPluginsTest,
       test_oversized_jar_does_not_affect_subsequent_valid_jar) {
  const auto oversized_archive_path = root_ / "oversized.jar";
  const auto valid_archive_path = root_ / "valid.jar";
  const auto oversized_content = makePluginXml(kMaxJetBrainsPluginXmlSize + 1U);
  createPluginArchive(oversized_archive_path,
                      oversized_content,
                      kMaxJetBrainsPluginXmlSize + 1U);
  createPluginArchive(valid_archive_path, makePluginXml(1024), 1024);

  EXPECT_EQ(attributesFromJar(oversized_archive_path.string()), nullptr);
  EXPECT_NE(attributesFromJar(valid_archive_path.string()), nullptr);
}

TEST_F(JetbrainsPluginsTest, test_fileNameIsLikeVersionedLibraryName) {
  // Versioned filenames
  ASSERT_TRUE(fileNameIsLikeVersionedLibraryName("kotlin-stdlib-1.5.0.jar"));
  ASSERT_TRUE(fileNameIsLikeVersionedLibraryName("kotlin-stdlib-m5.jar"));
  ASSERT_TRUE(fileNameIsLikeVersionedLibraryName("kotlin-stdlib-M5.jar"));
  ASSERT_TRUE(fileNameIsLikeVersionedLibraryName("jsr305-3.0.2.jar"));

  // non-versioned filenames
  ASSERT_FALSE(
      fileNameIsLikeVersionedLibraryName("kotlin-stdlib-1.5.0-sources.jar"));
  ASSERT_FALSE(fileNameIsLikeVersionedLibraryName("kotlin-stdlib.jar"));
  ASSERT_FALSE(fileNameIsLikeVersionedLibraryName("kotlin-stdlib-sources.jar"));
  ASSERT_FALSE(fileNameIsLikeVersionedLibraryName("banana-plugin.jar"));
  ASSERT_FALSE(fileNameIsLikeVersionedLibraryName("resources.jar"));
}

TEST_F(JetbrainsPluginsTest, test_putMoreLikelyPluginJarsFirst) {
  std::vector<std::string> files;

  // Resources are last
  files = {"/test-plugin/lib/resources.jar",
           "/test-plugin/lib/kotlin-stdlib.jar"};
  putMoreLikelyPluginJarsFirst("banana", files);
  ASSERT_EQ(files[0], "/test-plugin/lib/kotlin-stdlib.jar");
  ASSERT_EQ(files[1], "/test-plugin/lib/resources.jar");

  // Suffix is a digit is last
  files = {"/test-plugin/lib/json-2.8.0.jar",
           "/test-plugin/lib/completion-ranking.jar",
           "/test-plugin/lib/junit-m5.jar"};
  putMoreLikelyPluginJarsFirst("banana", files);
  ASSERT_EQ(files[0], "/test-plugin/lib/completion-ranking.jar");
  ASSERT_EQ(files[1], "/test-plugin/lib/junit-m5.jar");
  ASSERT_EQ(files[2], "/test-plugin/lib/json-2.8.0.jar");

  // Plugin name match is first
  files = {"/test-plugin/lib/plugin.jar", "/test-plugin/lib/banana-stdlib.jar"};
  putMoreLikelyPluginJarsFirst("banana", files);
  ASSERT_EQ(files[0], "/test-plugin/lib/banana-stdlib.jar");
  ASSERT_EQ(files[1], "/test-plugin/lib/plugin.jar");

  // Plugins ending with -idea.jar are last
  files = {"/test-plugin/lib/banana-idea.jar",
           "/test-plugin/lib/banana-stdlib.jar"};
  putMoreLikelyPluginJarsFirst("banana", files);
  ASSERT_EQ(files[0], "/test-plugin/lib/banana-stdlib.jar");
  ASSERT_EQ(files[1], "/test-plugin/lib/banana-idea.jar");

  // Plugins named database-plugin.jar are last
  files = {"/test-plugin/lib/database-plugin.jar",
           "/test-plugin/lib/banana-stdlib-common.jar"};
  putMoreLikelyPluginJarsFirst("banana", files);
  ASSERT_EQ(files[0], "/test-plugin/lib/banana-stdlib-common.jar");
  ASSERT_EQ(files[1], "/test-plugin/lib/database-plugin.jar");

  // Shorter names first
  files = {"/test-plugin/lib/android-base-common.jar",
           "/test-plugin/lib/android.jar"};
  putMoreLikelyPluginJarsFirst("banana", files);
  ASSERT_EQ(files[0], "/test-plugin/lib/android.jar");
  ASSERT_EQ(files[1], "/test-plugin/lib/android-base-common.jar");
}
} // namespace tables
} // namespace osquery

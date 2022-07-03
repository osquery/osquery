/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for file
// Spec file: specs/utility/file.table

#include <fstream>

#include <osquery/filesystem/filesystem.h>
#include <osquery/tests/integration/tables/helper.h>
#include <osquery/utils/info/platform_type.h>

namespace osquery {
namespace table_tests {

namespace {

const std::vector<std::string> kFileNameList{
    // In order to test MBCS support, here's a japanese word
    // that *should* mean "dictionary"
    "辞書.txt"

    "file-table-test.txt",
};

}

class FileTests : public testing::Test {
 public:
  boost::filesystem::path directory;

  virtual void SetUp() {
    setUpEnvironment();
    initializeFilesystemAPILocale();

    directory =
        boost::filesystem::temp_directory_path() /
        boost::filesystem::unique_path("test-integration-file-table.%%%%-%%%%");

    ASSERT_TRUE(boost::filesystem::create_directory(directory));

    for (const auto& file_name : kFileNameList) {
      auto filepath = directory / boost::filesystem::path(file_name);

      {
        auto fout = std::ofstream(filepath.native(), std::ios::out);
        fout.open(filepath.string(), std::ios::out);
        fout << "test";
      }
    }
  }

  virtual void TearDown() {
    boost::filesystem::remove_all(directory);
  }
};

boost::optional<std::size_t> getRowIndexForFileName(
    const QueryData& data, const std::string& file_name) {
  auto it = std::find_if(data.begin(),
                         data.end(),

                         [&](const Row& row) -> bool {
                           if (row.count("filename") == 0) {
                             return false;
                           }

                           return row.at("filename") == file_name;
                         });

  if (it == data.end()) {
    return boost::none;
  }

  return std::distance(data.begin(), it);
}

TEST_F(FileTests, test_sanity) {
  std::string path_constraint =
      (directory / boost::filesystem::path("%.txt")).string();
  QueryData data = execute_query("select * from file where path like \"" +
                                 path_constraint + "\"");
  EXPECT_EQ(data.size(), kFileNameList.size());

  ValidationMap row_map = {{"path", FileOnDisk},
                           {"directory", DirectoryOnDisk},
                           {"filename", NonEmptyString},
                           {"inode", IntType},
                           {"uid", NonNegativeInt},
                           {"gid", NonNegativeInt},
                           {"mode", NormalType},
                           {"device", IntType},
                           {"size", NonNegativeInt},
                           {"block_size", NonNegativeInt},
                           {"atime", NonNegativeInt},
                           {"mtime", NonNegativeInt},
                           {"ctime", NonNegativeInt},
                           {"btime", NonNegativeInt},
                           {"hard_links", IntType},
                           {"symlink", IntType},
                           {"type", NonEmptyString}};
#ifdef WIN32
  row_map["attributes"] = NormalType;
  row_map["volume_serial"] = NormalType;
  row_map["file_id"] = NormalType;
  row_map["product_version"] = NormalType;
  row_map["file_version"] = NormalType;
  row_map["original_filename"] = NormalType;
#endif

#ifdef __APPLE__
  row_map["bsd_flags"] = NormalType;
#endif

  for (const auto& test_file_name : kFileNameList) {
    auto opt_index = getRowIndexForFileName(data, test_file_name);
    ASSERT_TRUE(opt_index.has_value());

    auto index = opt_index.value();
    const auto& row = data.at(index);

    auto expected_path = directory.string();

#if WIN32
    expected_path += "\\";
#else
    expected_path += "/";
#endif

    expected_path += test_file_name;

    ASSERT_EQ(row.at("path"), expected_path);
    ASSERT_EQ(row.at("directory"), directory.string());
    ASSERT_EQ(row.at("filename"), test_file_name);
  }

  validate_rows(data, row_map);

  if (isPlatform(PlatformType::TYPE_LINUX)) {
    validate_container_rows(
        "file", row_map, "path like \"" + path_constraint + "\"");
  }
}

} // namespace table_tests
} // namespace osquery

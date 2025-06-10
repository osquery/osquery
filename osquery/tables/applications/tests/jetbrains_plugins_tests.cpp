/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>
#include <osquery/tables/applications/jetbrains_plugins.h>
#include <osquery/tests/test_util.h>

namespace osquery {
namespace tables {
class JetbrainsPluginsTest : public ::testing::Test {};

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

/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <mach/mach.h>
#include <unistd.h>

#include <cstring>
#include <memory>

#include <gtest/gtest.h>

#include <osquery/events/darwin/es_utils.h>

namespace osquery {

class EndpointSecurityUtilsTests : public testing::Test {};

TEST_F(EndpointSecurityUtilsTests, test_process_properties_ids) {
  audit_token_t token{};
  mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
  ASSERT_EQ(task_info(mach_task_self(),
                      TASK_AUDIT_TOKEN,
                      reinterpret_cast<task_info_t>(&token),
                      &count),
            KERN_SUCCESS);

  const char* path = "/usr/bin/true";
  es_file_t executable{};
  executable.path.data = path;
  executable.path.length = std::strlen(path);

  es_process_t process{};
  process.audit_token = token;
  process.executable = &executable;

  auto ec = std::make_shared<EndpointSecurityEventContext>();
  getProcessProperties(&process, ec);

  EXPECT_EQ(ec->pid, getpid());
  EXPECT_EQ(ec->path, path);
  EXPECT_EQ(ec->uid, getuid());
  EXPECT_EQ(ec->euid, geteuid());
  EXPECT_EQ(ec->gid, getgid());
  EXPECT_EQ(ec->egid, getegid());
}

} // namespace osquery

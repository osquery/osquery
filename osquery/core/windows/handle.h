/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/utils/system/system.h>

#include <osquery/utils/status/status.h>

#include <string>

namespace osquery {

class Handle {
  HANDLE _h;

 public:
  Handle();
  ~Handle();

  /// open a Windows object directory by name with OPEN_DIRECTORY access mask
  Status openDirObj(const std::wstring& directory);

  /// open a Windows symbolic link by name with SYMBOLIC_LINK_QUERY access mask
  Status openSymLinkObj(const std::wstring& symlink);

  HANDLE getAsHandle();

  void close();
  bool valid();
};
} // namespace osquery

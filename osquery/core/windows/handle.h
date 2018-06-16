/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <windows.h>
#include <string>

#include <osquery/status.h>

namespace osquery {
namespace tables {

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
} // namespace tables
} // namespace osquery

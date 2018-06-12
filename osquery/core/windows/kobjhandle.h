/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#define _WIN32_DCOM

#include <Windows.h>
#include <string>

namespace osquery {
namespace tables {

class KObjHandle {
  HANDLE _h;

 public:
  KObjHandle();
  ~KObjHandle();

  bool openDirObj(std::wstring directory);
  bool openSymLinkObj(std::wstring symlink);

  HANDLE getAsHandle();

  void close();
  bool valid();
};
}
}

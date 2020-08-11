/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/utils/system/filepath.h>

#include <climits>
#include <cstdlib>
#include <cstring>
#include <string>

namespace osquery {

const std::string canonicalize_file_name(const char* name) {
#ifdef PATH_MAX
  // On supported platforms where PATH_MAX is defined we can pass null
  // as buffer, and allow libc to alloced space
  // On centos/ubuntu libc will use realloc so we will be able to resolve
  // any path
  // On darwin libc will allocate PATH_MAX buffer for us
  char* resolved = realpath(name, nullptr);
  std::string result = (resolved == nullptr) ? name : resolved;
  free(resolved);
#else
#warning PATH_MAX is undefined, please read comment below
  // PATH_MAX is not defined, very likely it's not officially supported
  // os, our best guess is _PC_PATH_MAX if available
  // In case of failure fallback to "safe" buffer of 8K

  long int path_max = pathconf(name, _PC_PATH_MAX);
  if (path_max <= 0) {
    path_max = 8 * 1024;
  }
  char* buffer = static_cast<char*>(malloc(path_max));
  char* resolved = realpath(name, buffer);
  std::string result = (resolved == nullptr) ? name : resolved;
  free(buffer);
#endif
  return result;
}

} // namespace osquery

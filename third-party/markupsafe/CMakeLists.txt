# Copyright (c) 2018-present, Trail of Bits, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION 3.13.1)

function(markupsafeMain)
  set(name "markupsafe")
  set(base_url "https://s3.amazonaws.com/osquery-packages/third-party/pre-built/linux-x86_64")
  set(file_name "MarkupSafe-1.1.0-cp37-cp37m-manylinux1_x86_64.whl")

  if(DEFINED PLATFORM_LINUX)
    # Original SHA1 was 17ad72c7ce71a33144455048af1a5a3538ca1750
    set(hash "d9ac82be533394d341b41d78aca7ed0e0f4ba5a2231602e2f05aa87f25c51672")
  elseif(DEFINED PLATFORM_MACOS)
    # Original SHA1 was eb3e78cf203e2cd0eaa406ccf157cb613f9f28d8
    set(hash "aa")
  elseif(DEFINED PLATFORM_WINDOWS)
    # Original SHA1 was 0bbf7dc728394c47e375cb62e6690ab8cc5fa396
    set(hash "aa")
  elseif(DEFINED PLATFORM_FREEBSD)
    # Original SHA1 was 925a0b34f901f99aeadd4d91a1dd676b3eed494f
    set(hash "aa")
  else()
    return()
  endif()

  importRemotePythonModule("${name}" "${base_url}" "${file_name}" "${hash}")
endfunction()

markupsafeMain()


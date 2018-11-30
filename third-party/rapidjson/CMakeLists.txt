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

function(rapidjsonMain)
  set(name "rapidjson")
  set(version "1.1.0")

  if(DEFINED PLATFORM_LINUX)
    set(hash "f9a3d4e71cb72f00372696fb6c2c14094cec30519a692982de5b893a3562f244")
  elseif(DEFINED PLATFORM_MACOS)
    set(hash "ab8c220677cc03424d0683e36542a9dcd4eac1ff99ceae70007ce6e2462da9fa")
  elseif(DEFINED PLATFORM_WINDOWS)
    set(hash "62d59198edd5851d2c990d0e68edf7fbb633bb2816ed22adbdede03e688b0b67")
  else()
    return()
  endif()

  set(anchor_file "include/rapidjson/rapidjson.h")

  importThirdPartyBinaryLibrary("${name}" "${version}" "${hash}" "interface" "${anchor_file}")
endfunction()

rapidjsonMain()

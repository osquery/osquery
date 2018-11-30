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

function(sqliteMain)
  set(name "sqlite")
  set(version "3.24.0")

  if(DEFINED PLATFORM_LINUX)
    set(hash "d4fe4e10c01f508210670bf1a67d0445491df8fe7322161e3322b912529e33f0")
  elseif(DEFINED PLATFORM_MACOS)
    set(hash "995b47f65dc70f0ee76b0aa700e8ed3135e914ad3671c5ee43eab6d964b13a6a")
  elseif(DEFINED PLATFORM_WINDOWS)
  	set(hash "0f5ac78b7a9dafd2d5a900f33b36390390b3dca909e71fefb29379763fe1099e")
  else()
    return()
  endif()

  set(anchor_file "lib/libsqlite3.a")

  importThirdPartyBinaryLibrary("${name}" "${version}" "${hash}" "imported" "${anchor_file}")

  set(additional_libs "dl")
  if(DEFINED PLATFORM_LINUX)
    list(APPEND additional_libs
      thirdparty_pthread
    )
  endif()

  set_target_properties(thirdparty_sqlite PROPERTIES
    IMPORTED_LOCATION "${importThirdPartyBinaryLibrary_baseFolderPath}/${anchor_file}"
    INTERFACE_LINK_LIBRARIES "${additional_libs}"
  )
endfunction()

sqliteMain()

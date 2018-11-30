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

function(zlibMain)
  set(name "zlib")
  set(version "1.2.11")

  if(DEFINED PLATFORM_LINUX)
    set(hash "c6dfd85ce6c440fbaead6d4a3246d7771ed2b9b9f9e8c43257f57e0881d390e9")
  elseif(DEFINED PLATFORM_MACOS)
    set(hash "7f9b44ca67eadb2c6dcf6b86688cb759b77b772858dae2a2380c032c7c1d9edd")
  elseif(DEFINED PLATFORM_WINDOWS)
  	set(hash "1685157a99c419e5150cc5f44a61ad1a1f5ddf414bf1a451ed9b6c7faf26d4bc")
  else()
    return()
  endif()

  set(anchor_file "lib/libz.a")

  importThirdPartyBinaryLibrary("${name}" "${version}" "${hash}" "imported" "${anchor_file}")

  set_target_properties(thirdparty_zlib PROPERTIES
    IMPORTED_LOCATION "${importThirdPartyBinaryLibrary_baseFolderPath}/${anchor_file}"
  )
endfunction()

zlibMain()

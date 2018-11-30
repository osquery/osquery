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

function(bzip2Main)
  set(name "bzip2")
  set(version "1.0.6")

  if(DEFINED PLATFORM_MACOS)
    add_library(thirdparty_bzip2 INTERFACE)
    target_link_libraries(thirdparty_bzip2 INTERFACE "bz2")

    return()

  elseif(DEFINED PLATFORM_LINUX)
    set(hash "1cc3eaf8fe78f19fcae9f71065b04bd2dedb4862081f1d1c96e0668f3df864c8")

  elseif(DEFINED PLATFORM_WINDOWS)
    set(hash "11001b5e353bc255a755284b9ed8baed01b6d9fe2a63e5e325124e8b998d48c2")

  else()
    return()
  endif()

  set(anchor_file "lib/libbz2.a")

  importThirdPartyBinaryLibrary("${name}" "${version}" "${hash}" "imported" "${anchor_file}")

  set_target_properties(thirdparty_bzip2 PROPERTIES
    IMPORTED_LOCATION "${importThirdPartyBinaryLibrary_baseFolderPath}/${anchor_file}"
  )
endfunction()

bzip2Main()

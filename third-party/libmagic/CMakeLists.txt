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

function(libmagicMain)
  set(name "libmagic")
  set(version "5.32")

  if(DEFINED PLATFORM_LINUX)
    set(hash "e6c7144360b29d672db7a98cdfe55dc80812c2100b4a111d65f98e78404835aa")
  elseif(DEFINED PLATFORM_MACOS)
    set(hash "66efdaf945b8d04751aa337ef0529ded53fcd7e3b85fb8dfd9e4c40a562ffa6d")
  else()
    return()
  endif()

  set(anchor_file "lib/libmagic.a")

  importThirdPartyBinaryLibrary("${name}" "${version}" "${hash}" "imported" "${anchor_file}")

  set_target_properties(thirdparty_libmagic PROPERTIES
    IMPORTED_LOCATION "${importThirdPartyBinaryLibrary_baseFolderPath}/${anchor_file}"
    INTERFACE_LINK_LIBRARIES "thirdparty_zlib"
  )
endfunction()

libmagicMain()

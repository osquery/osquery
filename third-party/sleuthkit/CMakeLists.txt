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

function(sleuthkitMain)
  set(name "sleuthkit")
  set(version "4.6.1")

  if(DEFINED PLATFORM_LINUX)
    set(hash "e9d63528b0b0e868453e1d9a26e29137b222e6b682e53415fccaa41783ea2e24")
  elseif(DEFINED PLATFORM_MACOS)
    set(hash "a841486e4972f262baf195d1e5ec91e9800d6f3934689407b270efc8ba465e51")
  else()
    return()
  endif()

  set(anchor_file "lib/libtsk.a")

  importThirdPartyBinaryLibrary("${name}" "${version}" "${hash}" "imported" "${anchor_file}")

  set_target_properties(thirdparty_sleuthkit PROPERTIES
    IMPORTED_LOCATION "${importThirdPartyBinaryLibrary_baseFolderPath}/${anchor_file}"
  )
endfunction()

sleuthkitMain()

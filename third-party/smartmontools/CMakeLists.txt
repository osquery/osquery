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

function(smartmontoolsMain)
  set(name "smartmontools")
  set(version "0.3.1")

  if(DEFINED PLATFORM_LINUX)
    set(hash "a63ecfbd80eb715c1278770c9be72d45578bd9650fc31196956d3a87dd3b2a66")
  elseif(DEFINED PLATFORM_MACOS)
    set(hash "2ad496686cef94cf46bbf040d6a1d9aa8e051d2281246bfc7517329fc4695e67")
  else()
    return()
  endif()

  set(anchor_file "lib/libsmartctl.a")

  importThirdPartyBinaryLibrary("${name}" "${version}" "${hash}" "imported" "${anchor_file}")

  set_target_properties(thirdparty_smartmontools PROPERTIES
    IMPORTED_LOCATION "${importThirdPartyBinaryLibrary_baseFolderPath}/${anchor_file}"
  )
endfunction()

smartmontoolsMain()

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

function(lldpdMain)
  set(name "lldpd")
  set(version "0.9.6")

  if(DEFINED PLATFORM_LINUX)
    set(hash "27c0b6e6faf1863db025b95e8217e715cffc51b960b1d09e8fe9235b5ef203d8")
  elseif(DEFINED PLATFORM_MACOS)
    set(hash "f9d5d5c0c2514e7d51914ffc747a068b8a82602ca62e44b65f02857f015e0d3f")
  else()
    return()
  endif()

  set(anchor_file "lib/liblldpctl.a")

  importThirdPartyBinaryLibrary("${name}" "${version}" "${hash}" "imported" "${anchor_file}")

  set_target_properties(thirdparty_lldpd PROPERTIES
    IMPORTED_LOCATION "${importThirdPartyBinaryLibrary_baseFolderPath}/${anchor_file}"
  )
endfunction()

lldpdMain()

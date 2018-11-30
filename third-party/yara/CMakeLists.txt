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

function(yaraMain)
  set(name "yara")
  set(version "3.7.1")

  if(DEFINED PLATFORM_LINUX)
    set(hash "4706e8312c531c436b03be4ea429a94dbd06e2cd392764febc9e259777c8fc98")
  elseif(DEFINED PLATFORM_MACOS)
    set(hash "8cf4dfeb1e5f93fda206a200c1bce070c11bd486c1c335ede570980cdd196b0b")
  else()
    return()
  endif()

  set(anchor_file "lib/libyara.a")

  importThirdPartyBinaryLibrary("${name}" "${version}" "${hash}" "imported" "${anchor_file}")

  set(additional_dependencies
    thirdparty_openssl
  )

  if(DEFINED PLATFORM_LINUX)
    list(APPEND additional_dependencies "libbsd.a")
  endif()

  set_target_properties(thirdparty_yara PROPERTIES
    IMPORTED_LOCATION "${importThirdPartyBinaryLibrary_baseFolderPath}/${anchor_file}"
    INTERFACE_LINK_LIBRARIES "${additional_dependencies}"
  )
endfunction()

yaraMain()

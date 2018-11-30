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

function(opensslMain)
  set(name "openssl")
  set(version "1.0.2o")

  if(DEFINED PLATFORM_LINUX)
    set(hash "73472b9cf2d050b3cdda404144d28244b52d89b538b82de95acaaa98e282a1ea")
  elseif(DEFINED PLATFORM_MACOS)
    set(hash "39c59c34a497b365af0895de2b3e65e89c03f14c846084902ad3a77f943c3457")
  elseif(DEFINED PLATFORM_WINDOWS)
    set(hash "71144e5754cb19c32bad2ba298a3cf24e3fde4a012334c622c84e9a8cdc91ef8")
  else()
    return()
  endif()

  set(anchor_file "lib/libssl.a")

  set(additional_lib
    lib/libcrypto.a
  )

  importThirdPartyBinaryLibrary("${name}" "${version}" "${hash}" "imported" "${anchor_file}" ${additional_lib})

  set_target_properties(thirdparty_openssl PROPERTIES
    IMPORTED_LOCATION "${importThirdPartyBinaryLibrary_baseFolderPath}/${anchor_file}"
    INTERFACE_LINK_LIBRARIES "${importThirdPartyBinaryLibrary_baseFolderPath}/${additional_lib}"
  )
endfunction()

opensslMain()

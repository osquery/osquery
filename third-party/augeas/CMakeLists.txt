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

function(augeasMain)
  set(name "augeas")
  set(version "1.9.0")

  if(DEFINED PLATFORM_LINUX)
    set(hash "ff21a672ec7d6ae313eabe32a458d2d4528ad086559a24e9d70638da10983b37")
  elseif(DEFINED PLATFORM_MACOS)
    set(hash "7330e0fcfbcea6f58d199916238c47078f3ea2ba85ac4ed2fa74fcb63e034b1c")
  else()
    return()
  endif()

  set(anchor_file "lib/libaugeas.a")

  set(additional_library
    "lib/libfa.a"
  )

  importThirdPartyBinaryLibrary("${name}" "${version}" "${hash}" "imported" "${anchor_file}" ${additional_library})

  set_target_properties(thirdparty_augeas PROPERTIES
    IMPORTED_LOCATION "${importThirdPartyBinaryLibrary_baseFolderPath}/${anchor_file}"
    INTERFACE_LINK_LIBRARIES "${importThirdPartyBinaryLibrary_baseFolderPath}/${additional_library}"
  )
endfunction()

augeasMain()

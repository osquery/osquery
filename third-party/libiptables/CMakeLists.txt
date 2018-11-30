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

function(libiptablesMain)
  if(NOT DEFINED PLATFORM_LINUX)
    return()
  endif()

  set(name "libiptables")
  set(version "1.8.0")
  set(hash "f32841cca13b8273f767d859b6c98f6fe7fea05cfc835ff192c794a5d417ba26")
  set(anchor_file "lib/libip4tc.a")

  set(additional_libraries
    lib/libip6tc.a
    lib/libiptc.a
  )

  importThirdPartyBinaryLibrary("${name}" "${version}" "${hash}" "imported" "${anchor_file}" ${additional_libraries})

  foreach(additional_lib ${additional_libraries})
    list(APPEND additional_link_libs "${importThirdPartyBinaryLibrary_baseFolderPath}/${additional_lib}")
  endforeach()

  set_target_properties(thirdparty_libiptables PROPERTIES
    IMPORTED_LOCATION "${importThirdPartyBinaryLibrary_baseFolderPath}/${anchor_file}"
    INTERFACE_LINK_LIBRARIES "${additional_link_libs}"
  )
endfunction()

libiptablesMain()

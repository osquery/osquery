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

function(libdevmapperMain)
  if(NOT DEFINED PLATFORM_LINUX)
    return()
  endif()

  set(name "libdevmapper")
  set(version "2.2.02.173")
  set(hash "54fc7a991f42e3693fa3aa9cafe39f0b65a6fe29620f3146fd05f1a1f1bf1eae")
  set(anchor_file "lib/liblvm2app.a")

  set(additional_libraries
    lib/liblvm-internal.a
    lib/libdevmapper.a
    lib/libdaemonclient.a
  )

  importThirdPartyBinaryLibrary("${name}" "${version}" "${hash}" "imported" "${anchor_file}" ${additional_libraries})

  foreach(additional_lib ${additional_libraries})
    list(APPEND additional_link_libs "${importThirdPartyBinaryLibrary_baseFolderPath}/${additional_lib}")
  endforeach()

  set_target_properties(thirdparty_libdevmapper PROPERTIES
    IMPORTED_LOCATION "${importThirdPartyBinaryLibrary_baseFolderPath}/${anchor_file}"
    INTERFACE_LINK_LIBRARIES "${additional_link_libs}"
  )
endfunction()

libdevmapperMain()

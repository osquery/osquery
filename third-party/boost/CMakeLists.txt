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

function(boostMain)
  set(name "boost")
  set(version "1.66.0")

  if(DEFINED PLATFORM_LINUX)
    set(hash "3a24d65730beb3a718ee443eaedac40033d349582eeb83664ea2529080c812ba")
  elseif(DEFINED PLATFORM_MACOS)
    set(hash "69c884d27838a11f9a45b78e03eb12a425d554dac4ad8c6ef19f91e63e945286")
  elseif(DEFINED PLATFORM_WINDOWS)
    set(hash "5530174b75b67c3c8e59f2ae62c3e18fea1b5e55c795ff19b40fb75cf93dfb51")
  else()
    message(SEND_ERROR "Unsupported platform")
  endif()

  set(anchor_file "lib/libboost_system-mt.a")

  set(additional_libraries
    lib/libboost_chrono-mt.a
    lib/libboost_context-mt.a
    lib/libboost_coroutine-mt.a
    lib/libboost_filesystem-mt.a
    lib/libboost_regex-mt.a
    lib/libboost_thread-mt.a
  )

  importThirdPartyBinaryLibrary("${name}" "${version}" "${hash}" "imported" "${anchor_file}" ${additional_libraries})

  foreach(additional_lib ${additional_libraries})
    list(APPEND additional_link_libs "${importThirdPartyBinaryLibrary_baseFolderPath}/${additional_lib}")
  endforeach()

  set_target_properties(thirdparty_boost PROPERTIES
    IMPORTED_LOCATION "${importThirdPartyBinaryLibrary_baseFolderPath}/${anchor_file}"
    INTERFACE_LINK_LIBRARIES "${additional_link_libs}"
  )
endfunction()

boostMain()

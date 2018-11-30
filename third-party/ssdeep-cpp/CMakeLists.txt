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

function(ssdeepCppMain)
  set(name "ssdeep-cpp")
  set(version "2.14.1")

  if(DEFINED PLATFORM_LINUX)
    set(hash "d8248655050987524dc383d55d7b148803b18331cdbcb8bfd2a8198ca210298b")
  elseif(DEFINED PLATFORM_MACOS)
    set(hash "93f11f81eab1cc06bf11fd28bc42d7b9d02972e3705f864a9f8ef0f5ca90abcc")
  else()
    return()
  endif()

  set(anchor_file "lib/libfuzzy.a")

  importThirdPartyBinaryLibrary("${name}" "${version}" "${hash}" "imported" "${anchor_file}")

  set_target_properties(thirdparty_ssdeep-cpp PROPERTIES
    IMPORTED_LOCATION "${importThirdPartyBinaryLibrary_baseFolderPath}/${anchor_file}"
  )
endfunction()

ssdeepCppMain()

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

function(librdkafkaMain)
  set(name "librdkafka")
  set(version "0.11.3")

  if(DEFINED PLATFORM_LINUX)
    set(hash "a8cece2c04522243ee53fd85130c4c6e2874ba27261bef554e74afed7425641b")
  elseif(DEFINED PLATFORM_MACOS)
    set(hash "61790b76923d0005734db6209d99cd2c262cf2227500261244c208918e8b79b7")
  else()
    return()
  endif()

  set(anchor_file "lib/librdkafka.a")

  set(additional_lib
    lib/librdkafka++.a
  )

  importThirdPartyBinaryLibrary("${name}" "${version}" "${hash}" "imported" "${anchor_file}" ${additional_lib})

  set_target_properties(thirdparty_librdkafka PROPERTIES
    IMPORTED_LOCATION "${importThirdPartyBinaryLibrary_baseFolderPath}/${anchor_file}"
    INTERFACE_LINK_LIBRARIES "${importThirdPartyBinaryLibrary_baseFolderPath}/${additional_lib}"
  )
endfunction()

librdkafkaMain()

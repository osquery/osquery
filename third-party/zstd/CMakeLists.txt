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

function(zstdMain)
  set(name "zstd")
  set(version "1.2.0")

  if(DEFINED PLATFORM_LINUX)
    set(hash "f9397aeea5816a7cabd0e7040be86e569d2ffd84832a2e3c4e4bda224d6e42a5")
  elseif(DEFINED PLATFORM_MACOS)
    set(hash "4cd66f8c05f735ccf6c1457116ddb4cb2b1b0260458bb3c1476475721c9d70d9")
  elseif(DEFINED PLATFORM_WINDOWS)
  	set(hash "c214705dfd057b2e9b9e613c88131ccfde22c2f43787af37828ccf3f9bec918d")
  else()
    return()
  endif()

  set(anchor_file "lib/libzstd.a")

  importThirdPartyBinaryLibrary("${name}" "${version}" "${hash}" "imported" "${anchor_file}")

  set_target_properties(thirdparty_zstd PROPERTIES
    IMPORTED_LOCATION "${importThirdPartyBinaryLibrary_baseFolderPath}/${anchor_file}"
  )
endfunction()

zstdMain()

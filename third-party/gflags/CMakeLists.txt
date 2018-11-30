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

function(gflagsMain)
  set(name "gflags")
  set(version "2.2.1")

  if(DEFINED PLATFORM_LINUX)
    set(hash "5e0813ea29d5ba739c089ae21dccf5b7d4ec6f7a7d9550da0834476fade2b60c")
  elseif(DEFINED PLATFORM_MACOS)
    set(hash "217fd2573443981bc8e521fcf4d8201ba4d3c29cace1b9a537f94be08df7ebb6")
  elseif(DEFINED PLATFORM_WINDOWS)
    set(hash "a7bb0676d7ac0338cfa71f48f5e0d83332470e1fcd0223aa697f1a0fd2e0789a")
  else()
    return()
  endif()

  set(anchor_file "lib/libgflags.a")

  set(additional_library
    lib/libgflags_nothreads.a
  )

  importThirdPartyBinaryLibrary("${name}" "${version}" "${hash}" "imported" "${anchor_file}" ${additional_library})

  set_target_properties(thirdparty_gflags PROPERTIES
    IMPORTED_LOCATION "${importThirdPartyBinaryLibrary_baseFolderPath}/${anchor_file}"
    INTERFACE_LINK_LIBRARIES "${importThirdPartyBinaryLibrary_baseFolderPath}/${additional_library}"
  )
endfunction()

gflagsMain()

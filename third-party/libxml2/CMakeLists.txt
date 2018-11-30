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

function(libxml2Main)
  set(name "libxml2")
  set(version "2.9.7")

  if(DEFINED PLATFORM_LINUX)
    set(hash "40f341caf6442347a130e614f7d1be3193656b7c5ad86a644a87f3b15282f7bf")
  elseif(DEFINED PLATFORM_MACOS)
    set(hash "15c240f914a430036847d19f18be54b86d0c78d54eff601f9b036b63481b420e")
  else()
    return()
  endif()

  set(anchor_file "lib/libxml2.a")

  importThirdPartyBinaryLibrary("${name}" "${version}" "${hash}" "imported" "${anchor_file}")

  set_target_properties(thirdparty_libxml2 PROPERTIES
    IMPORTED_LOCATION "${importThirdPartyBinaryLibrary_baseFolderPath}/${anchor_file}"
  )
endfunction()

libxml2Main()

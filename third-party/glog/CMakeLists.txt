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

function(glogMain)
  set(name "glog")
  set(version "0.3.5")

  if(DEFINED PLATFORM_LINUX)
    set(hash "1291104355f4373f22294d86eeb2e612d03ea1adbf7cbaef2083ca730e9df60c")
  elseif(DEFINED PLATFORM_MACOS)
    set(hash "91ccd947175a029da61447cc2f871798dc3756bc3adfc178cc782e4714e5a712")
  elseif(DEFINED PLATFORM_WINDOWS)
    set(hash "7c25024502db7e5ffaa0d7e851450946b9193fb093b815692763b619b4d55723")
  else()
    return()
  endif()

  set(anchor_file "lib/libglog.a")

  importThirdPartyBinaryLibrary("${name}" "${version}" "${hash}" "imported" "${anchor_file}")

  set_target_properties(thirdparty_glog PROPERTIES
    IMPORTED_LOCATION "${importThirdPartyBinaryLibrary_baseFolderPath}/${anchor_file}"
    INTERFACE_LINK_LIBRARIES thirdparty_gflags
  )
endfunction()

glogMain()

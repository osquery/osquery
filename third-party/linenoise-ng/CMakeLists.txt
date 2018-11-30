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

function(linenoisengMain)
  set(name "linenoise-ng")
  set(version "1.0.1")
  set(hash "")

  if(DEFINED PLATFORM_LINUX)
    set(hash "604e50db04ab61ef592bcb96941bb30b67e976ac5487f904eab6927d96b9f5e9")
  elseif(DEFINED PLATFORM_MACOS)
    set(hash "78030ddb7041e86cfdd8db60bf446a147fb4c82959319597b09dcf0877337cf9")
  elseif(DEFINED PLATFORM_WINDOWS)
  	set(hash "6dbc0acd2c2c02a93136c5a673f87463e3f619ee07fa6b20c5806a2d5bef7c05")
  else()
    return()
  endif()

  set(anchor_file "lib/liblinenoise.a")

  importThirdPartyBinaryLibrary("${name}" "${version}" "${hash}" "imported" "${anchor_file}")

  set_target_properties(thirdparty_linenoise-ng PROPERTIES
    IMPORTED_LOCATION "${importThirdPartyBinaryLibrary_baseFolderPath}/${anchor_file}"
  )
endfunction()

linenoisengMain()

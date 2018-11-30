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

function(libgpgerrorMain)
	if(NOT DEFINED PLATFORM_LINUX)
		return()
	endif()

  set(name "libgpg-error")
  set(version "1.27")
  set(hash "6976db62b22844015e934f7225b236c8c4851c515815efa9967575eadd6dabf5")
  set(anchor_file "lib/libgpg-error.a")

  importThirdPartyBinaryLibrary("${name}" "${version}" "${hash}" "imported" "${anchor_file}")

  set_target_properties(thirdparty_libgpg-error PROPERTIES
    IMPORTED_LOCATION "${importThirdPartyBinaryLibrary_baseFolderPath}/${anchor_file}"
  )
endfunction()

libgpgerrorMain()

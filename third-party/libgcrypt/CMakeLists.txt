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

function(libgcryptMain)
	if(NOT DEFINED PLATFORM_LINUX)
		return()
	endif()

  set(name "libgcrypt")
  set(version "1.8.1")
  set(hash "338bb77bac1565319f69a210db5b50e0410046628b05f9c5ed3521607cbbf711")
  set(anchor_file "lib/libgcrypt.a")

  importThirdPartyBinaryLibrary("${name}" "${version}" "${hash}" "imported" "${anchor_file}")

  set_target_properties(thirdparty_libgcrypt PROPERTIES
    IMPORTED_LOCATION "${importThirdPartyBinaryLibrary_baseFolderPath}/${anchor_file}"
    INTERFACE_LINK_LIBRARIES "thirdparty_libgpg-error"
  )
endfunction()

libgcryptMain()

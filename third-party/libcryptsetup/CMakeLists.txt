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

function(libcryptsetupMain)
	if(NOT DEFINED PLATFORM_LINUX)
		return()
	endif()

  set(name "libcryptsetup")
  set(version "1.7.5")
  set(hash "ebb53650592212d67ea8c0e49b48891eec64ef370743678881985490c09adeac")
  set(anchor_file "lib/libcryptsetup.a")

  importThirdPartyBinaryLibrary("${name}" "${version}" "${hash}" "imported" "${anchor_file}")

  set_target_properties(thirdparty_libcryptsetup PROPERTIES
    IMPORTED_LOCATION "${importThirdPartyBinaryLibrary_baseFolderPath}/${anchor_file}"
    INTERFACE_LINK_LIBRARIES "thirdparty_libgcrypt"
  )
endfunction()

libcryptsetupMain()

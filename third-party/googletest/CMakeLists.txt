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

function(gooletestMain)
  set(name "gtest")
  set(version "1.8.1")
  set(hash "9bf1fe5182a604b4135edc1a425ae356c9ad15e9b23f9f12a02e80184c3a249c")
  set(include_folder "googletest-release-${version}/googletest/include")
  set(anchor_file "${include_folder}/gtest/gtest.h")

  importThirdPartySourceLibrary("${name}" "${version}" "${hash}" "${anchor_file}" "${include_folder}")
  add_library(thirdparty_googletest ALIAS thirdparty_gtest)
endfunction()

gooletestMain()

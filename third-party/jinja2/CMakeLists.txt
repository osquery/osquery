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

function(jinja2Main)
  set(name "jinja2")
  set(base_url "https://s3.amazonaws.com/osquery-packages/third-party/pre-built/none")
  set(file_name "Jinja2-2.10-py2.py3-none-any.whl")

  # Original SHA1 was f14bb3e5021b2b0605dcd4865ac539cde04fe856
  set(hash "74c935a1b8bb9a3947c50a54766a969d4846290e1e788ea44c1392163723c3bd")

  importRemotePythonModule("${name}" "${base_url}" "${file_name}" "${hash}")
endfunction()

jinja2Main()


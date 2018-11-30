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

function(osquery_extensions_thrift_main)
  generateOsqueryExtensionsThriftOsquerycpp2()
endfunction()

function(generateOsqueryExtensionsThriftOsquerycpp2)
  add_library(osquery_extensions_thrift_osquery-cpp2
    gen/Extension.cpp
    gen/ExtensionManager.cpp
    gen/osquery_constants.cpp
    gen/osquery_types.cpp
  )

  target_link_libraries(osquery_extensions_thrift_osquery-cpp2 PUBLIC
    global_cxx_settings
    thirdparty_thrift
  )

  set(public_header_files
    gen/Extension.h
    gen/ExtensionManager.h
    gen/osquery_constants.h
    gen/osquery_types.h
  )

  generateIncludeNamespace(osquery_extensions_thrift_osquery-cpp2 "" "FILE_ONLY" ${public_header_files})
endfunction()

osquery_extensions_thrift_main()

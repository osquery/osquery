# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(yamlcppMain)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")

  add_library(thirdparty_yaml-cpp
    "${library_root}/src/binary.cpp"
    "${library_root}/src/convert.cpp"
    "${library_root}/src/depthguard.cpp"
    "${library_root}/src/directives.cpp"
    "${library_root}/src/emit.cpp"
    "${library_root}/src/emitfromevents.cpp"
    "${library_root}/src/emitter.cpp"
    "${library_root}/src/emitterstate.cpp"
    "${library_root}/src/emitterutils.cpp"
    "${library_root}/src/exceptions.cpp"
    "${library_root}/src/exp.cpp"
    "${library_root}/src/fptostring.cpp"
    "${library_root}/src/memory.cpp"
    "${library_root}/src/node.cpp"
    "${library_root}/src/node_data.cpp"
    "${library_root}/src/nodebuilder.cpp"
    "${library_root}/src/nodeevents.cpp"
    "${library_root}/src/null.cpp"
    "${library_root}/src/ostream_wrapper.cpp"
    "${library_root}/src/parse.cpp"
    "${library_root}/src/parser.cpp"
    "${library_root}/src/regex_yaml.cpp"
    "${library_root}/src/scanner.cpp"
    "${library_root}/src/scanscalar.cpp"
    "${library_root}/src/scantag.cpp"
    "${library_root}/src/scantoken.cpp"
    "${library_root}/src/simplekey.cpp"
    "${library_root}/src/singledocparser.cpp"
    "${library_root}/src/stream.cpp"
    "${library_root}/src/tag.cpp"
  )

  target_compile_definitions(thirdparty_yaml-cpp PRIVATE
    YAML_CPP_NO_CONTRIB
  )

  # yaml-cpp is built here as a static library, but its dll.h defaults
  # YAML_CPP_API to __declspec(dllimport) under MSVC unless told otherwise
  # (upstream's own src/CMakeLists.txt sets this for non-shared builds; this
  # wrapper does not use that file). Without it the library fails to compile
  # on Windows -- classes like Emitter and Parser would be declared dllimport
  # while being defined here -- and consumers would look for __imp_ symbols a
  # static lib does not export. PUBLIC so consumers see the same declarations.
  target_compile_definitions(thirdparty_yaml-cpp PUBLIC
    YAML_CPP_STATIC_DEFINE
  )

  target_link_libraries(thirdparty_yaml-cpp PRIVATE
    thirdparty_cxx_settings
  )

  set_target_properties(thirdparty_yaml-cpp PROPERTIES
    POSITION_INDEPENDENT_CODE ON
  )

  target_include_directories(thirdparty_yaml-cpp PRIVATE
    "${library_root}/include"
  )

  target_include_directories(thirdparty_yaml-cpp SYSTEM INTERFACE
    "${library_root}/include"
  )
endfunction()

yamlcppMain()

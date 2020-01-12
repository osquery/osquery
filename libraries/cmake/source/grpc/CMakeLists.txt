# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

include(cmake/protobuf.cmake)

function(grpcMain)
  set(gRPC_BUILD_TESTS OFF CACHE BOOL "" FORCE)
  # We don't want to depend from libnsl.so.1, it's missing from some newer distros like CentOS 8,
  # and it's not actually needed by any library gRPC uses, it's only required in adiag which is an executable.
  set(gRPC_BACKWARDS_COMPATIBILITY_MODE ON CACHE BOOL "" FORCE)
  set(gRPC_BUILD_GRPC_CPP_PLUGIN OFF CACHE BOOL "" FORCE)

  # Disable thirdparty zlib, gflags, cares and openssl module
  # instead use the osquery provided library
  set(gRPC_ZLIB_PROVIDER "" CACHE STRING "" FORCE)
  set(gRPC_GFLAGS_PROVIDER "" CACHE STRING "" FORCE)
  set(gRPC_PROTOBUF_PROVIDER "" CACHE STRING "" FORCE)
  set(gRPC_SSL_PROVIDER "" CACHE STRING "" FORCE)

  set(gRPC_CARES_PROVIDER "module" CACHE STRING "" FORCE)

  #set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")
  set(library_root "${OSQUERY_grpc_ROOT_DIR}")
  set(PROTOC_PATH "${CMAKE_CURRENT_BINARY_DIR}" CACHE STRING "" FORCE)

  set(CMAKE_CXX_STANDARD 17)
  add_subdirectory("${library_root}" "${CMAKE_CURRENT_BINARY_DIR}/submodule" EXCLUDE_FROM_ALL)

  set(cares_include_directory
    "${library_root}/third_party/cares/"
    "${library_root}/third_party/cares/cares/"
  )

  target_include_directories(grpc PRIVATE
    ${cares_include_directory}
  )

  target_link_libraries(grpc PRIVATE
    thirdparty_cxx_settings
    c-ares
    thirdparty_zlib
    thirdparty_openssl
    thirdparty_googletest
  )

  target_link_libraries(grpc++ PRIVATE
    thirdparty_cxx_settings
    c-ares
    thirdparty_zlib
    thirdparty_openssl
    thirdparty_googletest
  )

  add_library(thirdparty_grpc INTERFACE)

  target_link_libraries(thirdparty_grpc INTERFACE
    grpc
    grpc++
    gpr
    thirdparty_protobuf
  )

  target_include_directories(thirdparty_grpc INTERFACE
    "${CMAKE_CURRENT_BINARY_DIR}/submodule/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/third_party/protobuf/src/"
  )

  add_executable(grpc_cpp_plugin
    "${library_root}/src/compiler/cpp_plugin.cc"
    "${library_root}/src/compiler/cpp_generator.cc"
 )

  target_include_directories(grpc_cpp_plugin PRIVATE
    "${library_root}"
    "${library_root}/include"
  )

  target_link_libraries(grpc_cpp_plugin PUBLIC
    grpc
    thirdparty_protobuf
  )

  target_link_libraries(grpc_cpp_plugin PRIVATE
    thirdparty_cxx_settings
  )

endfunction()

grpcMain()


# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryProtoMain)
  if(DEFINED PLATFORM_LINUX)
    generateContainerdProtos()
  endif()
endfunction()

function(generateContainerdProtos)
  # grpc library is imported via Findgrpc.cmake in the main library imports
  # Use protoc and grpc_cpp_plugin built from the grpc library
  # Get the actual location of the built executables
  get_target_property(PROTOC_EXECUTABLE protoc RUNTIME_OUTPUT_DIRECTORY)
  if(NOT PROTOC_EXECUTABLE)
    set(PROTOC_EXECUTABLE "${PROTOC_PATH}")
  endif()
  set(PROTOC_EXECUTABLE "${PROTOC_EXECUTABLE}/protoc")

  get_target_property(GRPC_CPP_PLUGIN_DIR grpc_cpp_plugin RUNTIME_OUTPUT_DIRECTORY)
  if(NOT GRPC_CPP_PLUGIN_DIR)
    set(GRPC_CPP_PLUGIN_DIR "${CMAKE_BINARY_DIR}/libs/src/grpc")
  endif()
  set(GRPC_CPP_PLUGIN_EXECUTABLE "${GRPC_CPP_PLUGIN_DIR}/grpc_cpp_plugin")

  # Define imported protobuf dependencies
  # These are the google protobuf protos that our containerd protos import
  set(PROTOBUF_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/libraries/cmake/source/grpc/src/third_party/protobuf/src")
  set(PROTOBUF_PROTO_DEPS
    "${PROTOBUF_INCLUDE_DIR}/google/protobuf/any.proto"
    "${PROTOBUF_INCLUDE_DIR}/google/protobuf/empty.proto"
    "${PROTOBUF_INCLUDE_DIR}/google/protobuf/field_mask.proto"
    "${PROTOBUF_INCLUDE_DIR}/google/protobuf/timestamp.proto"
  )

  add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/containerd
    COMMAND cmake -E make_directory ${CMAKE_CURRENT_BINARY_DIR}/containerd
  )

  set(containerd_proto_files
    containers
    tasks
    namespaces
    images
    snapshots
  )

  foreach(proto_file_name ${containerd_proto_files})
    add_custom_command(
      OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/containerd/${proto_file_name}.pb.h
             ${CMAKE_CURRENT_BINARY_DIR}/containerd/${proto_file_name}.pb.cc
      COMMAND ${PROTOC_EXECUTABLE} -I ${CMAKE_CURRENT_SOURCE_DIR}/containerd
              -I ${PROTOBUF_INCLUDE_DIR}
              --cpp_out=${CMAKE_CURRENT_BINARY_DIR}/containerd
              ${CMAKE_CURRENT_SOURCE_DIR}/containerd/${proto_file_name}.proto
      DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/containerd
      DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/containerd/${proto_file_name}.proto
      DEPENDS ${PROTOBUF_PROTO_DEPS}
      DEPENDS protoc
      VERBATIM
      COMMENT "Generating C++ protobuf for ${proto_file_name}"
    )

    add_custom_command(
      OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/containerd/${proto_file_name}.grpc.pb.h
             ${CMAKE_CURRENT_BINARY_DIR}/containerd/${proto_file_name}.grpc.pb.cc
      COMMAND ${PROTOC_EXECUTABLE} -I ${CMAKE_CURRENT_SOURCE_DIR}/containerd
              -I ${PROTOBUF_INCLUDE_DIR}
              --grpc_out=${CMAKE_CURRENT_BINARY_DIR}/containerd
              --plugin=protoc-gen-grpc=${GRPC_CPP_PLUGIN_EXECUTABLE}
              ${CMAKE_CURRENT_SOURCE_DIR}/containerd/${proto_file_name}.proto
      DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/containerd
      DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/containerd/${proto_file_name}.proto
      DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/containerd/${proto_file_name}.pb.h
      DEPENDS ${PROTOBUF_PROTO_DEPS}
      DEPENDS protoc
      DEPENDS grpc_cpp_plugin
      VERBATIM
      COMMENT "Generating C++ gRPC stub for ${proto_file_name}"
    )
  endforeach()

  # Create a library with the generated proto sources
  add_library(osquery_proto_containerd OBJECT
    ${CMAKE_CURRENT_BINARY_DIR}/containerd/containers.pb.cc
    ${CMAKE_CURRENT_BINARY_DIR}/containerd/containers.grpc.pb.cc
    ${CMAKE_CURRENT_BINARY_DIR}/containerd/tasks.pb.cc
    ${CMAKE_CURRENT_BINARY_DIR}/containerd/tasks.grpc.pb.cc
    ${CMAKE_CURRENT_BINARY_DIR}/containerd/namespaces.pb.cc
    ${CMAKE_CURRENT_BINARY_DIR}/containerd/namespaces.grpc.pb.cc
    ${CMAKE_CURRENT_BINARY_DIR}/containerd/images.pb.cc
    ${CMAKE_CURRENT_BINARY_DIR}/containerd/images.grpc.pb.cc
    ${CMAKE_CURRENT_BINARY_DIR}/containerd/snapshots.pb.cc
    ${CMAKE_CURRENT_BINARY_DIR}/containerd/snapshots.grpc.pb.cc
  )

  # Link against the built grpc library
  target_link_libraries(osquery_proto_containerd PUBLIC
    thirdparty_grpc
  )

  # Apply warning suppressions only to the generated protobuf code (PRIVATE linkage)
  # This prevents the suppressions from propagating to code that uses this library
  target_link_libraries(osquery_proto_containerd PRIVATE
    thirdparty_grpc_warning_suppressions
  )

  target_include_directories(osquery_proto_containerd PUBLIC
    ${CMAKE_CURRENT_BINARY_DIR}
  )

endfunction()

osqueryProtoMain()

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
  # grpc library is imported via Findgrpc.cmake in the main library imports.
  # Resolve the built tools by target so the path is correct under multi-config
  # generators (e.g. Ninja Multi-Config emits them in a per-config subdir). The
  # generate commands below already DEPENDS on these targets.
  set(PROTOC_EXECUTABLE "$<TARGET_FILE:protoc>")
  set(GRPC_CPP_PLUGIN_EXECUTABLE "$<TARGET_FILE:grpc_cpp_plugin>")

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

  set(containerd_service_protos
    containers
    tasks
    namespace
    images
    snapshots
  )

  # Message-only types the services import (no gRPC service, so .pb only).
  set(containerd_type_protos
    types/descriptor
    types/mount
    types/metrics
    types/task/task
  )

  # protobuf messages (.pb.{h,cc}) for every service and type proto. The service
  # files import the type files as "types/<name>.proto", so the source dir is the
  # single -I root under which both resolve.
  foreach(proto_file_name ${containerd_service_protos} ${containerd_type_protos})
    add_custom_command(
      OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/containerd/${proto_file_name}.pb.h
             ${CMAKE_CURRENT_BINARY_DIR}/containerd/${proto_file_name}.pb.cc
      COMMAND ${PROTOC_EXECUTABLE} -I ${CMAKE_CURRENT_SOURCE_DIR}/containerd
              -I ${PROTOBUF_INCLUDE_DIR}
              --cpp_out=${CMAKE_CURRENT_BINARY_DIR}/containerd
              ${CMAKE_CURRENT_SOURCE_DIR}/containerd/${proto_file_name}.proto
      DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/containerd
              ${CMAKE_CURRENT_SOURCE_DIR}/containerd/${proto_file_name}.proto
              ${PROTOBUF_PROTO_DEPS}
              protoc
      VERBATIM
      COMMENT "Generating C++ protobuf for ${proto_file_name}"
    )
  endforeach()

  # gRPC stubs (.grpc.pb.{h,cc}) for the services only; the type protos define no
  # service.
  foreach(proto_file_name ${containerd_service_protos})
    add_custom_command(
      OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/containerd/${proto_file_name}.grpc.pb.h
             ${CMAKE_CURRENT_BINARY_DIR}/containerd/${proto_file_name}.grpc.pb.cc
      COMMAND ${PROTOC_EXECUTABLE} -I ${CMAKE_CURRENT_SOURCE_DIR}/containerd
              -I ${PROTOBUF_INCLUDE_DIR}
              --grpc_out=${CMAKE_CURRENT_BINARY_DIR}/containerd
              --plugin=protoc-gen-grpc=${GRPC_CPP_PLUGIN_EXECUTABLE}
              ${CMAKE_CURRENT_SOURCE_DIR}/containerd/${proto_file_name}.proto
      DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/containerd
              ${CMAKE_CURRENT_SOURCE_DIR}/containerd/${proto_file_name}.proto
              ${CMAKE_CURRENT_BINARY_DIR}/containerd/${proto_file_name}.pb.h
              ${PROTOBUF_PROTO_DEPS}
              protoc
              grpc_cpp_plugin
      VERBATIM
      COMMENT "Generating C++ gRPC stub for ${proto_file_name}"
    )
  endforeach()

  # Collect generated sources: services contribute message + stub, types message
  # only.
  set(containerd_proto_sources)
  foreach(proto_file_name ${containerd_service_protos})
    list(APPEND containerd_proto_sources
      ${CMAKE_CURRENT_BINARY_DIR}/containerd/${proto_file_name}.pb.cc
      ${CMAKE_CURRENT_BINARY_DIR}/containerd/${proto_file_name}.grpc.pb.cc
    )
  endforeach()
  foreach(proto_file_name ${containerd_type_protos})
    list(APPEND containerd_proto_sources
      ${CMAKE_CURRENT_BINARY_DIR}/containerd/${proto_file_name}.pb.cc
    )
  endforeach()

  # Create a library with the generated proto sources
  add_library(osquery_proto_containerd OBJECT ${containerd_proto_sources})

  # Link against the built grpc library
  target_link_libraries(osquery_proto_containerd PUBLIC
    thirdparty_grpc
  )

  # Apply warning suppressions only to the generated protobuf code (PRIVATE linkage)
  # This prevents the suppressions from propagating to code that uses this library
  target_link_libraries(osquery_proto_containerd PRIVATE
    thirdparty_grpc_warning_suppressions
  )

  # ${CMAKE_CURRENT_BINARY_DIR} makes <containerd/*.pb.h> available to callers;
  # ${CMAKE_CURRENT_BINARY_DIR}/containerd resolves the generated cross-includes
  # ("types/<name>.pb.h") the service headers emit.
  target_include_directories(osquery_proto_containerd PUBLIC
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}/containerd
  )

endfunction()

osqueryProtoMain()

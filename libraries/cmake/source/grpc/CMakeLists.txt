# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(grpcMain)
  set(gRPC_BUILD_TESTS OFF CACHE BOOL "" FORCE)
  set(RE2_BUILD_TESTING OFF CACHE BOOL "" FORCE)
  # We don't want to depend from libnsl.so.1, it's missing from some newer distros like CentOS 8,
  # and it's not actually needed by any library gRPC uses, it's only required in adiag which is an executable.
  set(gRPC_BACKWARDS_COMPATIBILITY_MODE ON CACHE BOOL "" FORCE)
  set(gRPC_BUILD_GRPC_CPP_PLUGIN OFF CACHE BOOL "" FORCE)

  # Disable installation - we only need to build, not install
  set(gRPC_INSTALL OFF CACHE BOOL "" FORCE)
  set(protobuf_INSTALL OFF CACHE BOOL "" FORCE)

  # Disable thirdparty zlib, gflags, cares and openssl module
  # instead use the osquery provided library
  set(gRPC_ZLIB_PROVIDER "" CACHE STRING "" FORCE)
  set(gRPC_GFLAGS_PROVIDER "" CACHE STRING "" FORCE)
  set(gRPC_PROTOBUF_PROVIDER "module" CACHE STRING "" FORCE)
  set(gRPC_SSL_PROVIDER "" CACHE STRING "" FORCE)

  set(gRPC_CARES_PROVIDER "module" CACHE STRING "" FORCE)

  # Use patched source if available (set by importSourceSubmodule), otherwise use direct path
  if(DEFINED OSQUERY_grpc_ROOT_DIR)
    set(library_root "${OSQUERY_grpc_ROOT_DIR}")
  else()
    set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")
  endif()
  set(PROTOC_PATH "${CMAKE_CURRENT_BINARY_DIR}/submodule/third_party/protobuf" CACHE STRING "" FORCE)

  # Set ABSL_ROOT_DIR to the original source location since abseil isn't copied to patched source
  set(ABSL_ROOT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src/third_party/abseil-cpp" CACHE PATH "" FORCE)

  # gRPC v1.70.2 requires C++17 for CTAD and other modern C++ features
  # We patch gRPC's CMakeLists.txt to set CMAKE_CXX_STANDARD=17 on all platforms,
  # not just APPLE (see patches/src/cmakelists.patch)
  #
  # The patch checks "if (NOT DEFINED CMAKE_CXX_STANDARD)" so we must ensure it's
  # not defined. However, simply unsetting doesn't work - we need to ensure the
  # patched gRPC code actually USES the standard it sets.
  #
  # The issue is that CMAKE_CXX_STANDARD is a directory property that doesn't
  # propagate automatically. We need to set it in CACHE so all subdirectory targets
  # inherit it, but AFTER the patched gRPC code sets it, not before.
  #
  # Solution: Don't unset it here. Instead, modify the patch to SET it in cache.

  add_subdirectory("${library_root}" "${CMAKE_CURRENT_BINARY_DIR}/submodule" EXCLUDE_FROM_ALL)

  # Force C++17 on all gRPC targets that were just built
  # Even though we patch gRPC to set CMAKE_CXX_STANDARD=17 in cache,
  # some targets may not respect it. Explicitly set cxx_std_17 compile feature.
  set(grpc_targets
    address_sorting
    gpr
    grpc
    grpc_unsecure
    grpc++
    grpc++_unsecure
    upb_base_lib
    upb_hash_lib
    upb_json_lib
    upb_lex_lib
    upb_mem_lib
    upb_message_lib
    upb_mini_descriptor_lib
    upb_mini_table_lib
    upb_reflection_lib
    upb_textformat_lib
    upb_wire_lib
    utf8_range_lib
    libprotobuf-lite
    libprotobuf
    libprotoc
    protoc
  )

  foreach(target ${grpc_targets})
    if(TARGET ${target})
      target_compile_features(${target} PUBLIC cxx_std_17)
      # Disable GNU extensions - use strict C++17, not gnu++17
      set_target_properties(${target} PROPERTIES CXX_EXTENSIONS OFF)

      # Suppress warnings from gRPC/protobuf third-party code
      # These warnings occur because the osquery toolchain's Clang doesn't
      # support newer compiler attributes and warning groups used by gRPC
      target_compile_options(${target} PRIVATE
        -Wno-unknown-attributes           # Suppress "unknown attribute 'retain'" warnings
        -Wno-unknown-warning-option       # Suppress "unknown warning group" warnings
      )
    endif()
  endforeach()

  # Create alias for gRPC's built-in libprotobuf target
  # gRPC builds protobuf as "libprotobuf" when gRPC_PROTOBUF_PROVIDER="module"
  # Also include libprotoc for the protobuf compiler library
  add_library(thirdparty_protobuf INTERFACE)
  target_link_libraries(thirdparty_protobuf INTERFACE libprotobuf libprotoc)

  # Create alias for protoc executable built by gRPC
  if(NOT TARGET protobuf::protoc)
    add_executable(protobuf::protoc ALIAS protoc)
  endif()

  # Add abseil include directory to grpc targets
  # This is needed because abseil is built from the original source location
  # but grpc files are in the patched location
  target_include_directories(grpc PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/src/third_party/abseil-cpp"
  )
  target_include_directories(grpc++ PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/src/third_party/abseil-cpp"
  )

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

  # Create interface library for centralized gRPC/protobuf warning suppressions
  # This consolidates warning flags that were previously scattered across multiple CMakeLists
  add_library(thirdparty_grpc_warning_suppressions INTERFACE)
  target_compile_options(thirdparty_grpc_warning_suppressions INTERFACE
    # gRPC uses __attribute__((retain)) not supported by the osquery toolchain's Clang
    -Wno-unknown-attributes
    # gRPC uses warning groups not available in the osquery toolchain's Clang
    -Wno-unknown-warning-option
    # gRPC/protobuf use GNU variadic macro extensions
    -Wno-gnu-zero-variadic-macro-arguments
    # gRPC uses non-portable GCC-specific extensions
    -Wno-gcc-compat
    # Generated protobuf code has unused parameters
    -Wno-unused-parameter
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
    grpc_plugin_support
    thirdparty_protobuf
  )

  target_link_libraries(grpc_cpp_plugin PRIVATE
    thirdparty_cxx_settings
    thirdparty_grpc_warning_suppressions
  )

endfunction()

grpcMain()


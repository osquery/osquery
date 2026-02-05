# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

# CMake module for building BPF CO-RE programs with skeleton generation
# Requires: clang, bpftool, BTF support in kernel

# Function to generate vmlinux.h from kernel BTF
function(generate_vmlinux_h output_file)
  find_program(BPFTOOL bpftool
    PATHS
      "${OSQUERY_TOOLCHAIN_SYSROOT}/usr/bin"
      "${OSQUERY_TOOLCHAIN_SYSROOT}/usr/sbin"
      /usr/sbin
      /usr/local/sbin
      /sbin
    REQUIRED
  )
  
  set(vmlinux_btf "/sys/kernel/btf/vmlinux")
  
  if(NOT EXISTS "${vmlinux_btf}")
    message(FATAL_ERROR "Kernel BTF not found at ${vmlinux_btf}. "
                        "BPF CO-RE requires a kernel built with CONFIG_DEBUG_INFO_BTF=y")
  endif()
  
  add_custom_command(
    OUTPUT "${output_file}"
    COMMAND "${BPFTOOL}" btf dump file "${vmlinux_btf}" format c > "${output_file}"
    DEPENDS "${vmlinux_btf}"
    COMMENT "Generating vmlinux.h from kernel BTF"
    VERBATIM
  )
endfunction()

# Function to compile a BPF program and generate skeleton
# Arguments:
#   target_name: Name of the CMake target to create
#   bpf_source: Path to the .bpf.c source file
#   output_skeleton: Path where the skeleton .h file should be generated
function(build_bpf_skeleton target_name bpf_source output_skeleton)
  get_filename_component(bpf_source_abs "${bpf_source}" ABSOLUTE)
  get_filename_component(bpf_source_name "${bpf_source}" NAME_WE)
  
  # Find required tools
  find_program(BPFTOOL bpftool
    PATHS
      "${OSQUERY_TOOLCHAIN_SYSROOT}/usr/bin"
      "${OSQUERY_TOOLCHAIN_SYSROOT}/usr/sbin"
      /usr/sbin
      /usr/local/sbin
      /sbin
    REQUIRED
  )
  
  # Use clang from osquery toolchain
  set(CLANG_BPF "/usr/local/osquery-toolchain/usr/bin/clang")
  
  if(NOT EXISTS "${CLANG_BPF}")
    message(FATAL_ERROR "Clang not found at ${CLANG_BPF}")
  endif()
  
  # Output paths
  set(bpf_object "${CMAKE_CURRENT_BINARY_DIR}/${bpf_source_name}.bpf.o")
  
  # BPF compile flags
  set(BPF_CFLAGS
    -g
    -O2
    -target bpf
    -D__TARGET_ARCH_${CMAKE_SYSTEM_PROCESSOR}
    -D__BPF_TRACING__
    -nostdinc
    -I/usr/local/osquery-toolchain/usr/lib/clang/9.0.1/include  # For compiler builtins (stdbool.h, stdint.h, etc)
    -I/usr/local/osquery-toolchain/usr/include  # For kernel headers (linux/stddef.h, etc)
    -I${CMAKE_CURRENT_SOURCE_DIR}   # For our headers
    -I${CMAKE_SOURCE_DIR}/libraries/cmake/source/libbpf/src/include  # For linux/types.h etc
    -I${CMAKE_SOURCE_DIR}/libraries/cmake/source/libbpf/src/include/uapi  # For UAPI headers
    -I${CMAKE_SOURCE_DIR}/libraries/cmake/source/libbpf/include  # For additional kernel headers
  )
  
  # Compile BPF program to object file
  add_custom_command(
    OUTPUT "${bpf_object}"
    COMMAND "${CLANG_BPF}" ${BPF_CFLAGS} -c "${bpf_source_abs}" -o "${bpf_object}"
    DEPENDS "${bpf_source_abs}"
    COMMENT "Compiling BPF program ${bpf_source_name}"
    VERBATIM
  )
  
  # Generate BPF skeleton from object file
  get_filename_component(output_dir "${output_skeleton}" DIRECTORY)
  add_custom_command(
    OUTPUT "${output_skeleton}"
    COMMAND ${CMAKE_COMMAND} -E make_directory "${output_dir}"
    COMMAND "${BPFTOOL}" gen skeleton "${bpf_object}" > "${output_skeleton}"
    DEPENDS "${bpf_object}"
    COMMENT "Generating BPF skeleton for ${bpf_source_name}"
    VERBATIM
  )
  
  # Create target that depends on skeleton generation
  add_custom_target("${target_name}"
    DEPENDS "${output_skeleton}"
  )
endfunction()

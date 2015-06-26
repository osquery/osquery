# Set includes/compile options for kernel modules/extensions.
# Note: Assume OS X/Kext only.
set(KERNEL_BINARY_DIR "osquery.kext/Contents/MacOS/")
set(KERNEL_BINARY "${KERNEL_BINARY_DIR}/osquery")

set(CMAKE_C_FLAGS "")
set(CMAKE_CXX_FLAGS "")

set(KERNEL_C_FLAGS
  "-arch x86_64"
  -mkernel
  -nostdinc
  -fno-builtin
)
set(KERNEL_CXX_FLAGS ${KERNEL_C_FLAGS})

set(KERNEL_LINKER_FLAGS
  "-arch x86_64"
  -mkernel
  "-Xlinker -kext"
  -nostdlib
  -lkmod
)

JOIN("${KERNEL_LINKER_FLAGS}" " " KERNEL_LINKER_FLAGS)
include_directories("${CMAKE_SOURCE_DIR}/kernel/include")
include_directories("/System/Library/Frameworks/Kernel.framework/Headers")
include_directories("/Applications/Xcode.app/Contents/Developer/Platforms/\
MacOSX.platform/Developer/SDKs/MacOSX${APPLE_MIN_ABI}.sdk\
/System/Library/Frameworks/Kernel.framework/Headers")

add_definitions(
  -DOSQUERY_KERNEL_VERSION="${OSQUERY_BUILD_VERSION}"
)

# make debug (environment variable from Makefile)
if(DEFINED ENV{DEBUG})
  set(KERNEL_CXX_FLAGS ${KERNEL_CXX_FLAGS} -O0)
else()
  set(KERNEL_CXX_FLAGS ${KERNEL_CXX_FLAGS} -O3)
endif()

if(APPLE)
  set(KERNEL_TYPE "darwin")
elseif(LINUX)
  set(KERNEL_TYPE "linux")
endif()

set(BASE_KERNEL_SOURCES
  src/osquery.cpp
  src/circular_queue_kern.c
)

add_executable(base_kernel ${BASE_KERNEL_SOURCES})
set_target_properties(base_kernel PROPERTIES COMPILE_FLAGS ${KERNEL_C_FLAGS} ${KERNEL_CXX_FLAGS})
set_target_properties(base_kernel PROPERTIES LINK_FLAGS ${KERNEL_LINKER_FLAGS})
set_target_properties(base_kernel PROPERTIES EXCLUDE_FROM_ALL true)
set_target_properties(base_kernel PROPERTIES OUTPUT_NAME "${KERNEL_BINARY}")
add_dependencies(base_kernel kernel-layout)

# This should remain an opaque target.
add_custom_target(
  kernel-layout
  COMMAND mkdir -p "${CMAKE_BINARY_DIR}/kernel/${KERNEL_BINARY_DIR}"
  COMMAND
    cp "${CMAKE_SOURCE_DIR}/kernel/tools/deployment/Info.plist"
      "${CMAKE_BINARY_DIR}/kernel/osquery.kext/Contents/Info.plist"
  COMMENT "Create build directory structure for kernel extension"
)

# make kernel-build
add_custom_target(
  kernel-build
  DEPENDS kernel-layout base_kernel
  COMMAND echo "Building osquery kernel extension/module..."
)

# make kernel-load
add_custom_target(
  kernel-load
  DEPENDS kernel-build
  # Move the kernel extension bundle to /tmp to change ownership.
  # A virtual machine shared folder/filesystem may not allow root owned files.
  COMMAND sudo cp -R "${CMAKE_BINARY_DIR}/kernel/osquery.kext" "/tmp/"
  COMMAND sudo chown -R root:wheel "/tmp/osquery.kext"
  COMMAND sudo kextload -v "/tmp/osquery.kext"
)

# make kernel-provision
add_custom_target(
  kernel-provision
  COMMAND
  "${CMAKE_SOURCE_DIR}/kernel/tools/provision_${KERNEL_TYPE}.sh" enable
  WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  COMMENT "Preparing a development OS for kernel testing..."
)

# make kernel-deprovision
add_custom_target(
  kernel-deprovision
  COMMAND
  "${CMAKE_SOURCE_DIR}/kernel/tools/provision_${KERNEL_TYPE}.sh" disable
  WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  COMMENT "Restoring a development OS to disable kernel testing..."
)

add_custom_target(
  kernel-configure-target
  COMMAND
  "${CMAKE_SOURCE_DIR}/kernel/tools/provision_${KERNEL_TYPE}.sh" target
  WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  COMMENT "Preparing a development OS for kernel testing and debugging..."
)

add_custom_target(
  kernel-debug
  COMMAND dsymutil "${CMAKE_BINARY_DIR}/kernel/${KERNEL_BINARY}"
    -o "${CMAKE_BINARY_DIR}/kernel/${KERNEL_BINARY}.dSYM"
  COMMAND strip -S "${CMAKE_BINARY_DIR}/kernel/${KERNEL_BINARY}"
  COMMAND
  "${CMAKE_SOURCE_DIR}/kernel/tools/provision_${KERNEL_TYPE}.sh" debug
  WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  COMMENT "Generating symbols and launching a debugger with kernel target..."
)

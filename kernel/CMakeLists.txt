
# Set includes/compile options for kernel modules/extensions.
set(CMAKE_C_FLAGS "")
set(CMAKE_CXX_FLAGS "")

if(APPLE)
  set(KERNEL_BINARY_DIR "osquery.kext/Contents/MacOS/")
  set(KERNEL_BINARY "${KERNEL_BINARY_DIR}/osquery")

  # Set OS X platform-specific compiler flags.
  set(KERNEL_C_FLAGS
    "-arch x86_64"
    -mkernel
    -nostdinc
    -fno-builtin
  )

  # Set OS X platform-specific linker flags.
  set(KERNEL_LINKER_FLAGS
    "-arch x86_64"
    -mkernel
    "-Xlinker -kext"
    -nostdlib
    -lkmod
  )

  # Set OS X platform-specific include paths.
  include_directories("${CMAKE_SOURCE_DIR}/kernel/include")
  include_directories("${CMAKE_SOURCE_DIR}/kernel/src")
  include_directories("/System/Library/Frameworks/Kernel.framework/Headers")
  include_directories("/Applications/Xcode.app/Contents/Developer/Platforms/\
MacOSX.platform/Developer/SDKs/MacOSX${APPLE_MIN_ABI}.sdk\
/System/Library/Frameworks/Kernel.framework/Headers")
  set(KERNEL_TYPE "darwin")
elseif(LINUX)
  set(KERNEL_TYPE "linux")
endif()

# Join the set of linker flags, target properties want a " "-delimited set.
set(KERNEL_CXX_FLAGS ${KERNEL_C_FLAGS})
JOIN("${KERNEL_LINKER_FLAGS}" " " KERNEL_LINKER_FLAGS)

# Rewrite the osquery version defines to a kernel version in case they diverge.
add_definitions(
  -DOSQUERY_KERNEL_VERSION="${OSQUERY_BUILD_VERSION}"
)

# Define what debug builds change (environment variable from Makefile)
if(DEFINED ENV{DEBUG})
  set(KERNEL_CXX_FLAGS ${KERNEL_CXX_FLAGS} -O0)
else()
  set(KERNEL_CXX_FLAGS ${KERNEL_CXX_FLAGS} -O3)
endif()

# We will introduce a "kernel-test" mode that builds for pull requests and
# merges into master and includes additional unit-test facilities.
if(NOT OSQUERY_BUILD_RELEASE)
  add_definitions(-DKERNEL_TEST=1)
endif()

# The set of platform-agnostic implementations.
set(BASE_KERNEL_SOURCES
  src/circular_queue_kern.c
)

file(GLOB APPLE_KERNEL_PUBLISHER_SOURCES "src/publishers/darwin/*.c")
# Add a set of platform-specific files.
set(APPLE_KERNEL_SOURCES
  src/osquery.cpp
  ${APPLE_KERNEL_PUBLISHER_SOURCES}
)

# Define kernel targets, each should be an extension/module.
if(APPLE)
  # TODO: Remove the OS X requirement.
  add_executable(base_kernel ${APPLE_KERNEL_SOURCES} ${BASE_KERNEL_SOURCES})
  set_target_properties(base_kernel PROPERTIES COMPILE_FLAGS ${KERNEL_C_FLAGS} ${KERNEL_CXX_FLAGS})
  set_target_properties(base_kernel PROPERTIES LINK_FLAGS ${KERNEL_LINKER_FLAGS})
  set_target_properties(base_kernel PROPERTIES EXCLUDE_FROM_ALL true)
  set_target_properties(base_kernel PROPERTIES OUTPUT_NAME "${KERNEL_BINARY}")
  add_dependencies(base_kernel kernel-layout)
endif()

# Define layouts and dependencies/debug setup steps for each platform.
if(APPLE)
  # This should remain an opaque target.
  add_custom_target(
    kernel-layout
    COMMAND mkdir -p "${CMAKE_BINARY_DIR}/kernel/${KERNEL_BINARY_DIR}"
    COMMAND
      cp "${CMAKE_SOURCE_DIR}/kernel/tools/deployment/Info.plist"
        "${CMAKE_BINARY_DIR}/kernel/osquery.kext/Contents/Info.plist"
    COMMENT "Create build directory structure for kernel extension"
  )

  # make kernel-provision
  add_custom_target(
    kernel-deps
    COMMAND echo ""
    COMMAND echo "WARNING: Disabling OS X kernel extension signature checking..."
    COMMAND echo "WARNING: nvram boot-args=kext-dev-mode=1"
    COMMAND sudo nvram boot-args="kext-dev-mode=1"
    COMMAND echo "WARNING: Reboot required."
    COMMAND echo ""
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    COMMENT "Preparing a development OS for kernel testing..."
  )

  # make kernel-load
  add_custom_target(
    kernel-load
    DEPENDS kernel-build
    # Move the kernel extension bundle to /tmp to change ownership.
    # A virtual machine shared folder/filesystem may not allow root owned files.
    COMMAND sudo cp -R "${CMAKE_BINARY_DIR}/kernel/osquery.kext" "/tmp/"
    COMMAND sudo chown -R root:wheel "/tmp/osquery.kext"
    COMMAND sudo chmod -R 0644 "/tmp/osquery.kext"
    COMMAND sudo kextload -v "/tmp/osquery.kext"
    COMMAND echo "Wrote unsigned extension bundle: /tmp/osquery.kext"
  )

  # make kernel-unload
  add_custom_target(
    kernel-unload
    # Unload the kernel extension.
    COMMAND sudo "./kernel/tools/unload_with_retry.sh"
    COMMAND echo "Attempted to unload kernel extension with identifier:"
    COMMAND echo "com.facebook.security.osquery"
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  )

  # Additional helpful commands for configuring a debug environment for OS X.
  add_custom_target(
    kernel-configure-target
    COMMAND
    COMMAND echo ""
    COMMAND echo "WARNING: Configuring kernel to break/debug (BE CAREFUL)..."
    COMMAND echo "WARNING: nvram boot-args=\"kext-dev-mode=1 kcsuffix=kernel -v pmuflags=1\""
    COMMAND sudo nvram boot-args="kext-dev-mode=1 kcsuffix=kernel -v pmuflags=1"
    COMMAND echo "WARNING: Reboot required."
    COMMAND echo ""
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    COMMENT "Preparing a development OS for kernel testing and debugging..."
  )

  add_custom_target(
    kernel-debug
    COMMAND dsymutil "${CMAKE_BINARY_DIR}/kernel/${KERNEL_BINARY}"
      -o "${CMAKE_BINARY_DIR}/kernel/${KERNEL_BINARY}.dSYM"
    COMMAND strip -S "${CMAKE_BINARY_DIR}/kernel/${KERNEL_BINARY}"
    COMMAND
    "${CMAKE_SOURCE_DIR}/kernel/tools/${KERNEL_TYPE}.sh" debug
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    COMMENT "Generating symbols and launching a debugger with kernel target..."
  )

  add_custom_target(
    kernel-test
    COMMAND echo ""
    COMMAND echo "Running kernel tests requires root."
    COMMAND sudo $<TARGET_FILE:osquery_kernel_tests>
  )
elseif(LINUX)
  add_custom_target(
    base_kernel
    COMMAND echo "-- No base kernel for Linux"
  )

  add_custom_target(
    kernel-layout
    COMMAND echo "-- No kernel layout for Linux"
  )

  add_custom_target(
    kernel-deps
    COMMAND echo "-- No kernel dependencies for Linux"
  )

  add_custom_target(
    kernel-load
    COMMAND echo "-- No kernel load for Linux"
  )

  add_custom_target(
    kernel-unload
    COMMAND echo "-- No kernel unload for Linux"
  )

  add_custom_target(
    kernel-test
    COMMAND echo "-- No kernel test is run for Linux"
  )
else()
  add_custom_target(
    base_kernel
    COMMAND echo "-- No base kernel for unsupported platform"
  )

  add_custom_target(
    kernel-layout
    COMMAND echo "-- No kernel layout for unsupported platform"
  )

  add_custom_target(
    kernel-deps
    COMMAND echo "-- No kernel dependencies for unsupported platform"
  )

  add_custom_target(
    kernel-load
    COMMAND echo "-- No kernel load for unsupported platform"
  )

  add_custom_target(
    kernel-unload
    COMMAND echo "-- No kernel unload for unsupported platform"
  )

  add_custom_target(
    kernel-test
    COMMAND echo "-- No kernel test is run for unsupported platform"
  )
endif()

# make kernel-build
add_custom_target(
  kernel-build
  DEPENDS kernel-layout base_kernel
  COMMAND echo "-- Building osquery kernel extension/module..."
)

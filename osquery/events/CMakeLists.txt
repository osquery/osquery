if(APPLE)
  ADD_OSQUERY_LINK_ADDITIONAL("-framework CoreServices")
  ADD_OSQUERY_LINK_ADDITIONAL("-framework SystemConfiguration")
  ADD_OSQUERY_LINK_ADDITIONAL("-framework IOKit")
  ADD_OSQUERY_LINK_ADDITIONAL("-framework DiskArbitration")


  file(GLOB OSQUERY_EVENTS_DARWIN "darwin/*.cpp")
  ADD_OSQUERY_LIBRARY(FALSE osquery_events_darwin ${OSQUERY_EVENTS_DARWIN})
elseif(FREEBSD)
  file(GLOB OSQUERY_EVENTS_FREEBSD "freebsd/*.cpp")
  ADD_OSQUERY_LIBRARY(FALSE osquery_events_freebsd ${OSQUERY_EVENTS_FREEBSD})
elseif(WINDOWS)
  ADD_OSQUERY_LINK_CORE("wevtapi.lib")
  file(GLOB OSQUERY_EVENTS_WINDOWS "windows/*.cpp")
  ADD_OSQUERY_LIBRARY(FALSE osquery_events_windows ${OSQUERY_EVENTS_WINDOWS})
else()
  # See the root CMakeLists for SYSTEMD detection.
  # The udev library link is not available without systemd-devel.
  ADD_OSQUERY_LINK_ADDITIONAL("udev")
  ADD_OSQUERY_LINK_ADDITIONAL("audit")

  file(GLOB OSQUERY_EVENTS_LINUX "linux/*.cpp")
  ADD_OSQUERY_LIBRARY(FALSE osquery_events_linux ${OSQUERY_EVENTS_LINUX})
endif()

ADD_OSQUERY_LIBRARY(TRUE osquery_events
  events.cpp
)

if(NOT WINDOWS)
  file(GLOB OSQUERY_EVENTS_TESTS "tests/*.cpp")
  ADD_OSQUERY_TEST(TRUE ${OSQUERY_EVENTS_TESTS})

  file(GLOB OSQUERY_EVENTS_BENCHMARKS "benchmarks/*.cpp")
  if (LINUX)
    file(GLOB OSQUERY_EVENTS_PLATFORM_BENCHMARKS "linux/benchmarks/*.cpp")
  elseif (DARWIN)
    file(GLOB OSQUERY_EVENTS_PLATFORM_BENCHMARKS "darwin/benchmarks/*.cpp")
  endif()
  ADD_OSQUERY_BENCHMARK(
    ${OSQUERY_EVENTS_BENCHMARKS}
    ${OSQUERY_EVENTS_PLATFORM_BENCHMARKS}
  )

  # Kernel-related userland code.
  file(GLOB OSQUERY_EVENTS_KERNEL "kernel/*.cpp")
  ADD_OSQUERY_LIBRARY(FALSE osquery_events_kernel
    kernel.cpp
    ${OSQUERY_EVENTS_KERNEL}
  )

  # Special kernel test define when building non-SDK and non-Release.
  if(NOT OSQUERY_BUILD_RELEASE AND NOT OSQUERY_BUILD_SDK_ONLY)
    set_target_properties(osquery_events_kernel
      PROPERTIES COMPILE_DEFINITIONS "KERNEL_TEST=1")
  endif()

  file(GLOB OSQUERY_EVENTS_KERNEL_TESTS "kernel/tests/*.cpp")
  ADD_OSQUERY_KERNEL_TEST(${OSQUERY_EVENTS_KERNEL_TESTS})

  file(GLOB OSQUERY_EVENTS_KERNEL_BENCHMARKS "kernel/benchmarks/*.cpp")
  ADD_OSQUERY_KERNEL_BENCHMARK(${OSQUERY_EVENTS_KERNEL_BENCHMARKS})

  if(APPLE)
    file(GLOB OSQUERY_DARWIN_EVENTS_TESTS "darwin/tests/*.cpp")
    ADD_OSQUERY_TEST(FALSE ${OSQUERY_DARWIN_EVENTS_TESTS})
  elseif(LINUX)
    file(GLOB OSQUERY_LINUX_EVENTS_TESTS "linux/tests/*.cpp")
    ADD_OSQUERY_TEST(FALSE ${OSQUERY_LINUX_EVENTS_TESTS})
  endif()
endif()

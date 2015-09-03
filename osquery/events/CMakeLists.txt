if(APPLE)
  ADD_OSQUERY_LINK(FALSE "-framework CoreServices")
  ADD_OSQUERY_LINK(FALSE "-framework SystemConfiguration")
  ADD_OSQUERY_LINK(FALSE "-framework IOKit")
  ADD_OSQUERY_LINK(FALSE "-framework DiskArbitration")


  file(GLOB OSQUERY_EVENTS_DARWIN "darwin/*.cpp")
  ADD_OSQUERY_LIBRARY(FALSE osquery_events_darwin ${OSQUERY_EVENTS_DARWIN})
elseif(FREEBSD)
  file(GLOB OSQUERY_EVENTS_FREEBSD "freebsd/*.cpp")
  ADD_OSQUERY_LIBRARY(FALSE osquery_events_freebsd ${OSQUERY_EVENTS_FREEBSD})
else()
  ADD_OSQUERY_LINK(FALSE "udev")
  ADD_OSQUERY_LINK(FALSE "audit")

  file(GLOB OSQUERY_EVENTS_LINUX "linux/*.cpp")
  ADD_OSQUERY_LIBRARY(FALSE osquery_events_linux ${OSQUERY_EVENTS_LINUX})
endif()

ADD_OSQUERY_LIBRARY(TRUE osquery_events
  events.cpp
)

file(GLOB OSQUERY_EVENTS_TESTS "tests/*.cpp")
ADD_OSQUERY_TEST(TRUE ${OSQUERY_EVENTS_TESTS})

file(GLOB OSQUERY_EVENTS_BENCHMARKS "benchmarks/*.cpp")
ADD_OSQUERY_BENCHMARK(${OSQUERY_EVENTS_BENCHMARKS})

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

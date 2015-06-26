SET(OSQUERY_EVENTS_SOURCES "")

if(APPLE)
  ADD_OSQUERY_LINK(FALSE "-framework CoreServices")
  ADD_OSQUERY_LINK(FALSE "-framework SystemConfiguration")
  ADD_OSQUERY_LINK(FALSE "-framework IOKit")
  ADD_OSQUERY_LINK(FALSE "-framework DiskArbitration")

  ADD_OSQUERY_LIBRARY(FALSE osquery_events_darwin
    darwin/fsevents.cpp
    darwin/iokit_hid.cpp
    darwin/diskarbitration.cpp
    darwin/scnetwork.cpp
  )
elseif(FREEBSD)
  ADD_OSQUERY_LIBRARY(FALSE osquery_events_freebsd
  )
else()
  ADD_OSQUERY_LINK(FALSE "udev")

  ADD_OSQUERY_LIBRARY(FALSE osquery_events_linux
    linux/inotify.cpp
    linux/udev.cpp
  )
endif()

file(GLOB OSQUERY_KERNEL_QUEUE "kernel/*.cpp")
ADD_OSQUERY_LIBRARY(TRUE osquery_events
  events.cpp
  ${OSQUERY_KERNEL_QUEUE}
)

file(GLOB OSQUERY_KERNEL_QUEUE_TEST "kernel/tests/*.cpp")
ADD_OSQUERY_TEST(TRUE ${OSQUERY_KERNEL_QUEUE_TEST})

file(GLOB OSQUERY_EVENTS_TESTS "tests/*.cpp")
ADD_OSQUERY_TEST(TRUE ${OSQUERY_EVENTS_TESTS})

if(APPLE)
  file(GLOB OSQUERY_DARWIN_EVENTS_TESTS "darwin/tests/*.cpp")
  ADD_OSQUERY_TEST(FALSE ${OSQUERY_DARWIN_EVENTS_TESTS})
elseif(LINUX)
  file(GLOB OSQUERY_LINUX_EVENTS_TESTS "linux/tests/*.cpp")
  ADD_OSQUERY_TEST(FALSE ${OSQUERY_LINUX_EVENTS_TESTS})
endif()

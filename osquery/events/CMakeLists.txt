SET(OSQUERY_EVENTS_SOURCES "")

if(APPLE)
  ADD_OSQUERY_LINK(FALSE "-framework CoreServices")
  ADD_OSQUERY_LINK(FALSE "-framework SystemConfiguration")
  ADD_OSQUERY_LINK(FALSE "-framework IOKit")

  ADD_OSQUERY_LIBRARY(FALSE osquery_events_darwin
    darwin/fsevents.cpp
    darwin/iokit_hid.cpp
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

ADD_OSQUERY_LIBRARY(TRUE osquery_events
  events.cpp
)

ADD_OSQUERY_TEST(TRUE events_tests events_tests.cpp)
ADD_OSQUERY_TEST(TRUE events_database_tests events_database_tests.cpp)

if(APPLE)
  ADD_OSQUERY_TEST(FALSE fsevents_tests darwin/fsevents_tests.cpp)
elseif(LINUX)
  ADD_OSQUERY_TEST(FALSE inotify_tests linux/inotify_tests.cpp)
endif()

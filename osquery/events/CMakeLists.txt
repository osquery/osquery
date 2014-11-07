SET(OSQUERY_EVENTS_SOURCES "")

if(APPLE)
  ADD_OSQUERY_LINK("-framework CoreServices")
  ADD_OSQUERY_LINK("-framework SystemConfiguration")

  ADD_OSQUERY_LIBRARY(osquery_events_darwin
    darwin/fsevents.cpp
    darwin/scnetwork.cpp
  )
elseif(FREEBSD)
  ADD_OSQUERY_LIBRARY(osquery_events_freebsd
  )
else()
  ADD_OSQUERY_LIBRARY(osquery_events_linux
    linux/inotify.cpp
  )
endif()

ADD_OSQUERY_LIBRARY(osquery_events
  events.cpp
)

ADD_OSQUERY_TEST(events_tests events_tests.cpp)
ADD_OSQUERY_TEST(events_database_tests events_database_tests.cpp)

if(APPLE)
  ADD_OSQUERY_TEST(fsevents_tests darwin/fsevents_tests.cpp)
elseif(FREEBSD)
#  ADD_OSQUERY_TEST(fsevents_tests freebsd/events_tests.cpp)
else()
  ADD_OSQUERY_TEST(inotify_tests linux/inotify_tests.cpp)
endif()

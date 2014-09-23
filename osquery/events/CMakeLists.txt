SET(OSQUERY_EVENTS_SOURCES "")

if(APPLE)
  ADD_OSQUERY_LINK("-framework IOKit")
  ADD_OSQUERY_LINK("-framework CoreFoundation")
  ADD_OSQUERY_LINK("-framework Security")

  ADD_OSQUERY_LIBRARY(osquery_events_darwin
    darwin/fsevents.cpp
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
else()
  ADD_OSQUERY_TEST(inotify_tests linux/inotify_tests.cpp)
endif()

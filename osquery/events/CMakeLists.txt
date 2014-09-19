SET(OSQUERY_EVENTTYPES_TARGETS "")

if(APPLE)
  ADD_LIBRARY(osquery_eventtypes_darwin OBJECT
    darwin/fsevents.cpp
  )

  ADD_OSQUERY_LINK("-framework IOKit")
  ADD_OSQUERY_LINK("-framework CoreFoundation")
  ADD_OSQUERY_LINK("-framework Security")
  SET_OSQUERY_COMPILE(osquery_eventtypes_darwin)

  LIST(APPEND OSQUERY_EVENTTYPES_TARGETS 
    $<TARGET_OBJECTS:osquery_eventtypes_darwin>)
else()
  ADD_LIBRARY(osquery_eventtypes_linux OBJECT
    linux/inotify.cpp
  )

  SET_OSQUERY_COMPILE(osquery_eventtypes_linux)

  LIST(APPEND OSQUERY_EVENTTYPES_TARGETS $<TARGET_OBJECTS:osquery_eventtypes_linux>)
endif()

# Add the targets from above to libosquery (may change with plugins)
ADD_OSQUERY_LIB("${OSQUERY_EVENTTYPES_TARGETS}")

ADD_LIBRARY(osquery_events OBJECT
  events.cpp
)

SET_OSQUERY_COMPILE(osquery_events)

ADD_LIBRARY(osquery_testing_events
  $<TARGET_OBJECTS:osquery_database>
  $<TARGET_OBJECTS:osquery_events>
  ${OSQUERY_EVENTTYPES_TARGETS}
)

ADD_OSQUERY_TEST(events_tests events_tests.cpp osquery_testing_events)
ADD_OSQUERY_TEST(events_database_tests events_database_tests.cpp 
  osquery_testing_events)

if(APPLE)

else()
  ADD_OSQUERY_TEST(inotify_tests linux/inotify_tests.cpp
    osquery_testing_events)
endif()

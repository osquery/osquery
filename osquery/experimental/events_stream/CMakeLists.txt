# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryExperimentalEventsstreamMain)
  generateOsqueryExperimentalEventsstreamEventsstreamregistry()
  generateOsqueryExperimentalEventsstream()
endfunction()

function(generateOsqueryExperimentalEventsstreamEventsstreamregistry)
  # Originally osquery_experimental_eventsstream_eventsstreamregistry, shortened due to MSBuild not supporting long paths
  add_osquery_library(osquery_experimental_eventsstream_registry EXCLUDE_FROM_ALL events_stream_registry.cpp)

  enableLinkWholeArchive(osquery_experimental_eventsstream_registry)

  target_link_libraries(osquery_experimental_eventsstream_registry PUBLIC
    global_cxx_settings
    osquery_core
    osquery_utils
    thirdparty_boost
  )

  set(public_header_files
    events_stream_registry.h
  )

  generateIncludeNamespace(osquery_experimental_eventsstream_registry "osquery/experimental/events_stream" "FILE_ONLY" ${public_header_files})
endfunction()

function(generateOsqueryExperimentalEventsstream)
  add_osquery_library(osquery_experimental_eventsstream EXCLUDE_FROM_ALL events_stream.cpp)

  target_link_libraries(osquery_experimental_eventsstream PUBLIC
    global_cxx_settings
    osquery_experimental_eventsstream_registry
    osquery_core
    osquery_utils
    thirdparty_boost
  )

  set(public_header_files
    events_stream.h
  )

  generateIncludeNamespace(osquery_experimental_eventsstream "osquery/experimental/events_stream" "FILE_ONLY" ${public_header_files})
endfunction()

osqueryExperimentalEventsstreamMain()

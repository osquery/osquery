# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryEventsMain)
  if(OSQUERY_BUILD_TESTS)
    add_subdirectory("tests")
  endif()

  generateOsqueryEvents()
  generateOsqueryEventsEventsregistry()
endfunction()

function(generateOsqueryEvents)
  if(DEFINED PLATFORM_LINUX)
    list(APPEND source_files
      audit_flags.cpp
      file_events_flags.cpp
      linux/auditdnetlink.cpp
      linux/auditeventpublisher.cpp
      linux/inotify.cpp
      linux/syslog.cpp
      linux/udev.cpp
      linux/socket_events.cpp
    )

    if(OSQUERY_BUILD_BPF)
      list(APPEND source_files
        linux/bpf/bpferrorstate.cpp
        linux/bpf/bpfeventpublisher.cpp
        linux/bpf/filesystem.cpp
        linux/bpf/processcontextfactory.cpp
        linux/bpf/setrlimit.cpp
        linux/bpf/systemstatetracker.cpp
        linux/bpf/serializers.cpp
      )
    endif()

  elseif(DEFINED PLATFORM_MACOS)
    list(APPEND source_files
      audit_flags.cpp
      file_events_flags.cpp
      darwin/diskarbitration.cpp
      darwin/es_utils.cpp
      darwin/endpointsecurity.cpp
      darwin/endpointsecurity_fim.cpp
      darwin/event_taps.cpp
      darwin/fsevents.cpp
      darwin/iokit.cpp
      darwin/openbsm.cpp
      darwin/scnetwork.cpp
    )

  elseif(DEFINED PLATFORM_WINDOWS)
    list(APPEND source_files
      windows/evtsubscription.cpp
      windows/ntfs_event_publisher.cpp
      windows/usn_journal_reader.cpp
      windows/windowseventlogpublisher.cpp
      windows/windowseventlogparserservice.cpp
      windows/windowseventlogparser.cpp
    )
	
    if(OSQUERY_BUILD_ETW)
      list(APPEND source_files
        windows/etw/etw_user_session.cpp
        windows/etw/etw_publisher_processes.cpp
        windows/etw/etw_provider_config.cpp
        windows/etw/etw_post_processing_pipeline.cpp
        windows/etw/etw_kernel_session.cpp
        windows/etw/etw_controller.cpp
        windows/etw/etw_publisher.cpp
      )
    endif()	
  endif()

  add_osquery_library(osquery_events EXCLUDE_FROM_ALL
    ${source_files}
  )

  enableLinkWholeArchive(osquery_events)

  target_link_libraries(osquery_events PUBLIC
    osquery_cxx_settings
    osquery_core
    osquery_config
    osquery_events_eventsregistry
    osquery_hashing
    osquery_sql
    osquery_utils_conversions
    osquery_utils_expected
    osquery_utils_system_time
    thirdparty_boost
  )

  if(DEFINED PLATFORM_LINUX)
    target_link_libraries(osquery_events PUBLIC
      thirdparty_libaudit
      thirdparty_libudev
      thirdparty_util-linux
    )

    if(OSQUERY_BUILD_BPF)
      target_link_libraries(osquery_events PUBLIC
        thirdparty_ebpfpub
      )
    endif()

  elseif(DEFINED PLATFORM_WINDOWS)
    target_link_libraries(osquery_events PUBLIC
      plugins_config_parsers
    )
	
    if(OSQUERY_BUILD_ETW)
      target_link_libraries(osquery_events PUBLIC
        thirdparty_krabsetw
      )
    endif()
  
  endif()

  set(public_header_files
    pathset.h
  )

  generateIncludeNamespace(osquery_events "osquery/events" "FILE_ONLY" ${public_header_files})

  if(DEFINED PLATFORM_LINUX)
    set(platform_public_header_files
      linux/auditdnetlink.h
      linux/auditeventpublisher.h
      linux/inotify.h
      linux/process_events.h
      linux/process_file_events.h
      linux/selinux_events.h
      linux/apparmor_events.h
      linux/socket_events.h
      linux/syslog.h
      linux/udev.h
    )

    if(OSQUERY_BUILD_BPF)
      list(APPEND platform_public_header_files
        linux/bpf/bpferrorstate.h
        linux/bpf/bpfeventpublisher.h
        linux/bpf/filesystem.h
        linux/bpf/ifilesystem.h
        linux/bpf/iprocesscontextfactory.h
        linux/bpf/isystemstatetracker.h
        linux/bpf/processcontextfactory.h
        linux/bpf/setrlimit.h
        linux/bpf/systemstatetracker.h
        linux/bpf/serializers.h
        linux/bpf/uniquedir.h
      )
    endif()

  elseif(DEFINED PLATFORM_MACOS)
    set(platform_public_header_files
      darwin/diskarbitration.h
      darwin/es_utils.h
      darwin/endpointsecurity.h
      darwin/event_taps.h
      darwin/fsevents.h
      darwin/iokit.h
      darwin/openbsm.h
      darwin/scnetwork.h
    )

  elseif(DEFINED PLATFORM_WINDOWS)
    set(platform_public_header_files
      windows/evtsubscription.h
      windows/ntfs_event_publisher.h
      windows/usn_journal_reader.h
      windows/windowseventlogpublisher.h
      windows/windowseventlogparserservice.h
      windows/windowseventlogparser.h
    )
	
    if(OSQUERY_BUILD_ETW)
      list(APPEND platform_public_header_files
        windows/etw/etw_user_session.h
        windows/etw/etw_publisher_processes.h
        windows/etw/etw_publisher.h
        windows/etw/etw_provider_config.h
        windows/etw/etw_post_processing_pipeline.h
        windows/etw/etw_krabs.h
        windows/etw/etw_kernel_session.h
        windows/etw/etw_data_event.h
        windows/etw/etw_controller.h
        windows/etw/etw_concurrent_queue.h
      )
    endif()	
  endif()

  generateIncludeNamespace(osquery_events "osquery/events" "FULL_PATH" ${platform_public_header_files})

  add_test(NAME osquery_events_tests_eventsdatabasetests-test COMMAND osquery_events_tests_eventsdatabasetests-test)

  if(DEFINED PLATFORM_LINUX)
    add_test(NAME osquery_events_tests_syslogtests-test COMMAND osquery_events_tests_syslogtests-test)
    add_test(NAME osquery_events_tests_audittests-test COMMAND osquery_events_tests_audittests-test)
    add_test(NAME osquery_events_tests_processfileeventstests-test COMMAND osquery_events_tests_processfileeventstests-test)
    add_test(NAME osquery_events_tests_inotifytests-test COMMAND osquery_events_tests_inotifytests-test)

    if(OSQUERY_BUILD_BPF)
      add_test(NAME osquery_events_tests_bpftests-test COMMAND osquery_events_tests_bpftests-test)
    endif()
  endif()

  if(DEFINED PLATFORM_MACOS)
    add_test(NAME osquery_events_tests_fseventstests-test COMMAND osquery_events_tests_fseventstests-test)
  endif()

  if(DEFINED PLATFORM_WINDOWS)
    add_test(NAME osquery_events_tests_usnjournalreadertests-test COMMAND osquery_events_tests_usnjournalreadertests-test)
    add_test(NAME osquery_tables_events_tests_powershelleventstests-test COMMAND osquery_tables_events_tests_powershelleventstests-test)
    add_test(NAME osquery_tables_events_tests_windowseventstests-test COMMAND osquery_tables_events_tests_windowseventstests-test)

    if(OSQUERY_BUILD_ETW)
		add_test(NAME osquery_tables_events_tests_etwtests-test COMMAND osquery_tables_events_tests_etwtests-test)
    endif()		
  endif()
endfunction()

function(generateOsqueryEventsEventsregistry)
  add_osquery_library(osquery_events_eventsregistry EXCLUDE_FROM_ALL
    subscription.cpp
    eventer.cpp
    eventpublisherplugin.cpp
    events.cpp
    eventfactory.cpp
    eventsubscriberplugin.cpp
  )

  enableLinkWholeArchive(osquery_events_eventsregistry)

  target_link_libraries(osquery_events_eventsregistry PUBLIC
    osquery_cxx_settings
    osquery_core
    osquery_config
    osquery_dispatcher
    osquery_sql
  )

  set(public_header_files
    eventer.h
    eventfactory.h
    eventpublisher.h
    eventpublisherplugin.h
    events.h
    eventsubscriber.h
    eventsubscriberplugin.h
    pathset.h
    subscription.h
    types.h
  )

  generateIncludeNamespace(osquery_events_eventsregistry "osquery/events" "FILE_ONLY" ${public_header_files})

  add_test(NAME osquery_events_tests-test COMMAND osquery_events_tests-test)
endfunction()

osqueryEventsMain()

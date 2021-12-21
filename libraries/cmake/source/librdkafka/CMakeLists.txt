# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(librdkafkaMain)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")

  if(PLATFORM_LINUX)
    set(config_folder_path
      "${CMAKE_CURRENT_SOURCE_DIR}/config/linux/${TARGET_PROCESSOR}"
    )

  elseif(PLATFORM_WINDOWS)
    set(config_folder_path
      "${CMAKE_CURRENT_SOURCE_DIR}/config/windows/${TARGET_PROCESSOR}"
    )

  elseif(PLATFORM_MACOS)
    set(config_folder_path
      "${CMAKE_CURRENT_SOURCE_DIR}/config/macos/${TARGET_PROCESSOR}"
    )
  endif()

  add_library(thirdparty_rdkafka_c
    "${library_root}/src/crc32c.c"
    "${library_root}/src/lz4.c"
    "${library_root}/src/lz4frame.c"
    "${library_root}/src/lz4hc.c"
    "${library_root}/src/rdaddr.c"
    "${library_root}/src/rdavl.c"
    "${library_root}/src/rdbuf.c"
    "${library_root}/src/rdcrc32.c"
    "${library_root}/src/rddl.c"
    "${library_root}/src/rdfnv1a.c"
    "${library_root}/src/rdgz.c"
    "${library_root}/src/rdkafka_admin.c"
    "${library_root}/src/rdkafka_assignment.c"
    "${library_root}/src/rdkafka_assignor.c"
    "${library_root}/src/rdkafka_aux.c"
    "${library_root}/src/rdkafka_background.c"
    "${library_root}/src/rdkafka_broker.c"
    "${library_root}/src/rdkafka_buf.c"
    "${library_root}/src/rdkafka.c"
    "${library_root}/src/rdkafka_cert.c"
    "${library_root}/src/rdkafka_cgrp.c"
    "${library_root}/src/rdkafka_conf.c"
    "${library_root}/src/rdkafka_coord.c"
    "${library_root}/src/rdkafka_error.c"
    "${library_root}/src/rdkafka_event.c"
    "${library_root}/src/rdkafka_feature.c"
    "${library_root}/src/rdkafka_header.c"
    "${library_root}/src/rdkafka_idempotence.c"
    "${library_root}/src/rdkafka_interceptor.c"
    "${library_root}/src/rdkafka_lz4.c"
    "${library_root}/src/rdkafka_metadata.c"
    "${library_root}/src/rdkafka_metadata_cache.c"
    "${library_root}/src/rdkafka_mock.c"
    "${library_root}/src/rdkafka_mock_cgrp.c"
    "${library_root}/src/rdkafka_mock_handlers.c"
    "${library_root}/src/rdkafka_msg.c"
    "${library_root}/src/rdkafka_msgset_reader.c"
    "${library_root}/src/rdkafka_msgset_writer.c"
    "${library_root}/src/rdkafka_offset.c"
    "${library_root}/src/rdkafka_op.c"
    "${library_root}/src/rdkafka_partition.c"
    "${library_root}/src/rdkafka_pattern.c"
    "${library_root}/src/rdkafka_plugin.c"
    "${library_root}/src/rdkafka_queue.c"
    "${library_root}/src/rdkafka_range_assignor.c"
    "${library_root}/src/rdkafka_request.c"
    "${library_root}/src/rdkafka_roundrobin_assignor.c"
    "${library_root}/src/rdkafka_sasl.c"
    "${library_root}/src/rdkafka_sasl_oauthbearer.c"
    "${library_root}/src/rdkafka_sasl_plain.c"
    "${library_root}/src/rdkafka_sasl_scram.c"
    "${library_root}/src/rdkafka_ssl.c"
    "${library_root}/src/rdkafka_sticky_assignor.c"
    "${library_root}/src/rdkafka_subscription.c"
    "${library_root}/src/rdkafka_timer.c"
    "${library_root}/src/rdkafka_topic.c"
    "${library_root}/src/rdkafka_transport.c"
    "${library_root}/src/rdkafka_txnmgr.c"
    "${library_root}/src/rdkafka_zstd.c"
    "${library_root}/src/rdlist.c"
    "${library_root}/src/rdlog.c"
    "${library_root}/src/rdmap.c"
    "${library_root}/src/rdmurmur2.c"
    "${library_root}/src/rdports.c"
    "${library_root}/src/rdrand.c"
    "${library_root}/src/rdregex.c"
    "${library_root}/src/rdstring.c"
    "${library_root}/src/rdunittest.c"
    "${library_root}/src/rdvarint.c"
    "${library_root}/src/rdxxhash.c"
    "${library_root}/src/snappy.c"
    "${library_root}/src/tinycthread.c"
    "${library_root}/src/tinycthread_extra.c"
  )

  if(PLATFORM_POSIX)
    target_sources(thirdparty_rdkafka_c PRIVATE
      "${library_root}/src/rdhdrhistogram.c"
    )

  elseif(PLATFORM_WINDOWS)
    target_sources(thirdparty_rdkafka_c PRIVATE
      "${library_root}/src/rdkafka_sasl_win32.c"
      "${library_root}/src/regexp.c"
    )
  endif()

  target_compile_definitions(thirdparty_rdkafka_c PRIVATE
    XXH_NAMESPACE=RDKAFKA_
  )

  target_include_directories(thirdparty_rdkafka_c PRIVATE
    "${library_root}/src"
    "${config_folder_path}/dummy"
  )

  if(PLATFORM_POSIX)
    target_sources(thirdparty_rdkafka_c PRIVATE
      "${config_folder_path}"
    )
  endif()

  target_include_directories(thirdparty_rdkafka_c SYSTEM INTERFACE
    "${library_root}/src"
  )

  if(PLATFORM_POSIX)
    find_package(Threads REQUIRED)
    target_link_libraries(thirdparty_rdkafka_c PUBLIC
      Threads::Threads
    )

  elseif(PLATFORM_WINDOWS)
    target_link_libraries(thirdparty_rdkafka_c PUBLIC
      crypt32
      ws2_32
      secur32
    )
  endif()

  target_link_libraries(thirdparty_rdkafka_c
    PRIVATE
      thirdparty_c_settings

    PUBLIC
      thirdparty_openssl
      thirdparty_zlib
      thirdparty_zstd
  )

  if(PLATFORM_LINUX AND TARGET_PROCESSOR STREQUAL "aarch64")
    target_link_libraries(thirdparty_rdkafka_c PUBLIC
      ${CMAKE_DL_LIBS}
    )
  endif()

  if(PLATFORM_MACOS)
    target_link_libraries(thirdparty_rdkafka_c PUBLIC
      m
    )
  endif()

  target_compile_definitions(thirdparty_rdkafka_c PUBLIC
    LIBRDKAFKA_STATICLIB
  )

  if(PLATFORM_POSIX)
    target_compile_definitions(thirdparty_rdkafka_c PRIVATE
      WITH_STATIC_LIB_libcrypto
    )

  elseif(PLATFORM_WINDOWS)
    target_compile_definitions(thirdparty_rdkafka_c PRIVATE
      WITHOUT_WIN32_CONFIG
      WITH_SSL=1
      WITH_ZLIB=1
      WITH_SNAPPY=0
      WITH_ZSTD=1
      WITH_SASL_SCRAM=1
      WITH_SASL_OAUTHBEARER=1
      ENABLE_DEVEL=0
      WITH_PLUGINS=1
    )
  endif()

  add_library(thirdparty_rdkafka_cpp
    "${library_root}/src-cpp/ConfImpl.cpp"
    "${library_root}/src-cpp/ConsumerImpl.cpp"
    "${library_root}/src-cpp/HandleImpl.cpp"
    "${library_root}/src-cpp/HeadersImpl.cpp"
    "${library_root}/src-cpp/KafkaConsumerImpl.cpp"
    "${library_root}/src-cpp/MessageImpl.cpp"
    "${library_root}/src-cpp/MetadataImpl.cpp"
    "${library_root}/src-cpp/ProducerImpl.cpp"
    "${library_root}/src-cpp/QueueImpl.cpp"
    "${library_root}/src-cpp/RdKafka.cpp"
    "${library_root}/src-cpp/TopicImpl.cpp"
    "${library_root}/src-cpp/TopicPartitionImpl.cpp"
  )

  target_include_directories(thirdparty_rdkafka_cpp PRIVATE
    "${library_root}/src-cpp"
    "${config_folder_path}/dummy"
  )

  target_include_directories(thirdparty_rdkafka_cpp SYSTEM INTERFACE
    "${library_root}/src-cpp"
  )

  target_link_libraries(thirdparty_rdkafka_cpp
    PRIVATE
      thirdparty_cxx_settings

    PUBLIC
      thirdparty_rdkafka_c
  )

  add_library(thirdparty_librdkafka INTERFACE)
  target_link_libraries(thirdparty_librdkafka INTERFACE
    thirdparty_rdkafka_c
    thirdparty_rdkafka_cpp
  )

  set(public_include_folder "${CMAKE_CURRENT_BINARY_DIR}/include")
  set(source_include_header "${library_root}/src/rdkafka.h")
  set(dest_include_header "${public_include_folder}/librdkafka/rdkafka.h")

  add_custom_command(
    OUTPUT "${dest_include_header}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${public_include_folder}/librdkafka"
    COMMAND "${CMAKE_COMMAND}" -E create_symlink "${source_include_header}" "${dest_include_header}"
    MAIN_DEPENDENCY "${source_include_header}"
    COMMENT "Generating the librdkafka include folder"
    VERBATIM
  )

  add_custom_target(thirdparty_librdkafka_include_builder
    DEPENDS "${dest_include_header}"
  )

  add_dependencies(thirdparty_librdkafka
    thirdparty_librdkafka_include_builder
  )

  target_include_directories(thirdparty_librdkafka INTERFACE
    "${public_include_folder}"
  )
endfunction()

librdkafkaMain()

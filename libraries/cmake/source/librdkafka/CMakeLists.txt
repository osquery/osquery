# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(librdkafkaMain)
  generateLibrdkafka()
  generateLibrdkafkaxx()

  add_library(thirdparty_librdkafka INTERFACE)

  target_link_libraries(thirdparty_librdkafka INTERFACE
    thirdparty_librdkafka_c
    thirdparty_librdkafka_cxx
  )
endfunction()

function(generateLibrdkafka)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src/src")

  add_library(thirdparty_librdkafka_c
    "${library_root}/rdkafka.c"
    "${library_root}/rdkafka_broker.c"
    "${library_root}/rdkafka_msg.c"
    "${library_root}/rdkafka_topic.c"
    "${library_root}/rdkafka_conf.c"
    "${library_root}/rdkafka_timer.c"
    "${library_root}/rdkafka_offset.c"
    "${library_root}/rdkafka_transport.c"
    "${library_root}/rdkafka_buf.c"
    "${library_root}/rdkafka_queue.c"
    "${library_root}/rdkafka_op.c"
    "${library_root}/rdkafka_request.c"
    "${library_root}/rdkafka_cgrp.c"
    "${library_root}/rdkafka_pattern.c"
    "${library_root}/rdkafka_partition.c"
    "${library_root}/rdkafka_subscription.c"
    "${library_root}/rdkafka_assignor.c"
    "${library_root}/rdkafka_range_assignor.c"
    "${library_root}/rdkafka_roundrobin_assignor.c"
    "${library_root}/rdkafka_feature.c"
    "${library_root}/rdcrc32.c"
    "${library_root}/crc32c.c"
    "${library_root}/rdmurmur2.c"
    "${library_root}/rdaddr.c"
    "${library_root}/rdrand.c"
    "${library_root}/rdlist.c"
    "${library_root}/tinycthread.c"
    "${library_root}/tinycthread_extra.c"
    "${library_root}/rdlog.c"
    "${library_root}/rdstring.c"
    "${library_root}/rdkafka_event.c"
    "${library_root}/rdkafka_metadata.c"
    "${library_root}/rdregex.c"
    "${library_root}/rdports.c"
    "${library_root}/rdkafka_metadata_cache.c"
    "${library_root}/rdavl.c"
    "${library_root}/rdkafka_sasl.c"
    "${library_root}/rdkafka_sasl_plain.c"
    "${library_root}/rdkafka_interceptor.c"
    "${library_root}/rdkafka_msgset_writer.c"
    "${library_root}/rdkafka_msgset_reader.c"
    "${library_root}/rdkafka_header.c"
    "${library_root}/rdkafka_admin.c"
    "${library_root}/rdkafka_aux.c"
    "${library_root}/rdkafka_background.c"
    "${library_root}/rdkafka_idempotence.c"
    "${library_root}/rdvarint.c"
    "${library_root}/rdbuf.c"
    "${library_root}/rdunittest.c"
    "${library_root}/snappy.c"
    "${library_root}/rdhdrhistogram.c"
    "${library_root}/rdkafka_lz4.c"
    "${library_root}/lz4.c"
    "${library_root}/lz4frame.c"
    "${library_root}/lz4hc.c"
    "${library_root}/rddl.c"
    "${library_root}/rdkafka_plugin.c"
    "${library_root}/rdkafka_zstd.c"
    "${library_root}/rdkafka_sasl_scram.c"
    "${library_root}/rdgz.c"
  )

  if(DEFINED PLATFORM_WINDOWS)
    target_sources(thirdparty_librdkafka_c PRIVATE
      "${library_root}/rdkafka_sasl_win32.c"
      "${library_root}/regexp.c"
    )
  endif()

  configure_file(
    "${library_root}/rdkafka.h"
    "${CMAKE_CURRENT_BINARY_DIR}/include/librdkafka/rdkafka.h"
    COPYONLY
  )

  target_include_directories(thirdparty_librdkafka_c PRIVATE
    "${CMAKE_CURRENT_BINARY_DIR}/include/librdkafka"
  )

  target_compile_definitions(thirdparty_librdkafka_c PRIVATE
    LIBRDKAFKA_GIT_VERSION=\"v1.0.1\"
    XXH_NAMESPACE=rdkafka_
    XXH_PRIVATE_API
  )
  
  if(DEFINED PLATFORM_WINDOWS)
    target_compile_definitions(thirdparty_librdkafka_c PRIVATE
      WITH_ZSTD
      WITH_ZSTD_STATIC
      WITH_SSL
      WITH_ZLIB
      WITH_PLUGINS
      WITH_SASL_SCRAM
      WITH_HDRHISTOGRAM
    )
  endif()

  target_compile_definitions(thirdparty_librdkafka_c PUBLIC
    LIBRDKAFKA_STATICLIB
  )

  target_link_libraries(thirdparty_librdkafka_c PUBLIC
    thirdparty_openssl
    thirdparty_zlib
    thirdparty_zstd
  )

  target_link_libraries(thirdparty_librdkafka_c PRIVATE
    thirdparty_c_settings
  )

  target_include_directories(thirdparty_librdkafka_c PRIVATE
    "${library_root}"
  )

  if(DEFINED PLATFORM_LINUX)
    target_include_directories(thirdparty_librdkafka_c PRIVATE
      "${CMAKE_CURRENT_SOURCE_DIR}/config/${TARGET_PROCESSOR}/linux/dummy"
    )
  elseif(DEFINED PLATFORM_MACOS)
    target_include_directories(thirdparty_librdkafka_c PRIVATE
      "${CMAKE_CURRENT_SOURCE_DIR}/config/${TARGET_PROCESSOR}/macos/dummy"
    )
  endif()

  target_include_directories(thirdparty_librdkafka_c SYSTEM INTERFACE
    "${CMAKE_CURRENT_BINARY_DIR}/include"
  )
endfunction()

function(generateLibrdkafkaxx)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src/src-cpp")

  add_library(thirdparty_librdkafka_cxx
    "${library_root}/RdKafka.cpp"
    "${library_root}/ConfImpl.cpp"
    "${library_root}/HandleImpl.cpp"
    "${library_root}/ConsumerImpl.cpp"
    "${library_root}/ProducerImpl.cpp"
    "${library_root}/KafkaConsumerImpl.cpp"
    "${library_root}/TopicImpl.cpp"
    "${library_root}/TopicPartitionImpl.cpp"
    "${library_root}/MessageImpl.cpp"
    "${library_root}/HeadersImpl.cpp"
    "${library_root}/QueueImpl.cpp"
    "${library_root}/MetadataImpl.cpp"
  )

  configure_file(
    "${library_root}/rdkafkacpp.h"
    "${CMAKE_CURRENT_BINARY_DIR}/include/librdkafka/rdkafkacpp.h"
    COPYONLY
  )

  target_compile_definitions(thirdparty_librdkafka_cxx PUBLIC
    LIBRDKAFKA_STATICLIB
  )

  target_link_libraries(thirdparty_librdkafka_cxx PRIVATE
    thirdparty_cxx_settings
  )

  target_include_directories(thirdparty_librdkafka_cxx PRIVATE
    "${library_root}"
  )

  if(DEFINED PLATFORM_LINUX)
    target_include_directories(thirdparty_librdkafka_cxx PRIVATE
      "${CMAKE_CURRENT_SOURCE_DIR}/config/${TARGET_PROCESSOR}/linux/dummy"
    )
  elseif(DEFINED PLATFORM_MACOS)
    target_include_directories(thirdparty_librdkafka_cxx PRIVATE
      "${CMAKE_CURRENT_SOURCE_DIR}/config/${TARGET_PROCESSOR}/macos/dummy"
    )
  endif()

  target_include_directories(thirdparty_librdkafka_cxx SYSTEM INTERFACE
    "${CMAKE_CURRENT_BINARY_DIR}/include"
  )
endfunction()

librdkafkaMain()

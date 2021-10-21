# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(thriftMain)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src/lib/cpp")

  if(PLATFORM_WINDOWS)
    set(thrift_config_path "${CMAKE_CURRENT_SOURCE_DIR}/config/windows/${TARGET_PROCESSOR}")

  elseif(PLATFORM_LINUX)
    set(thrift_config_path "${CMAKE_CURRENT_SOURCE_DIR}/config/linux/${TARGET_PROCESSOR}")

  elseif(PLATFORM_MACOS)
    set(thrift_config_path "${CMAKE_CURRENT_SOURCE_DIR}/config/macos/${TARGET_PROCESSOR}")
  endif()

  add_library(thirdparty_thrift_settings INTERFACE)
  if(PLATFORM_WINDOWS)
    target_compile_options(thirdparty_thrift_settings INTERFACE
      "/source-charset:utf-8"
      "/execution-charset:utf-8"
    )

    target_compile_definitions(thirdparty_thrift_settings INTERFACE
      UNICODE
      _UNICODE
      BOOST_ALL_NO_LIB
    )
  endif()

  target_compile_definitions(thirdparty_thrift_settings INTERFACE
    __STDC_FORMAT_MACROS
    __STDC_LIMIT_MACROS
    THRIFT_STATIC_DEFINE
  )

  add_library(thirdparty_thrift_thrift
    "${library_root}/src/thrift/async/TAsyncChannel.cpp"
    "${library_root}/src/thrift/async/TAsyncProtocolProcessor.cpp"
    "${library_root}/src/thrift/async/TConcurrentClientSyncInfo.cpp"
    "${library_root}/src/thrift/async/TConcurrentClientSyncInfo.h"
    "${library_root}/src/thrift/concurrency/Monitor.cpp"
    "${library_root}/src/thrift/concurrency/Mutex.cpp"
    "${library_root}/src/thrift/concurrency/Thread.cpp"
    "${library_root}/src/thrift/concurrency/ThreadFactory.cpp"
    "${library_root}/src/thrift/concurrency/ThreadManager.cpp"
    "${library_root}/src/thrift/concurrency/TimerManager.cpp"
    "${library_root}/src/thrift/processor/PeekProcessor.cpp"
    "${library_root}/src/thrift/protocol/TBase64Utils.cpp"
    "${library_root}/src/thrift/protocol/TDebugProtocol.cpp"
    "${library_root}/src/thrift/protocol/TJSONProtocol.cpp"
    "${library_root}/src/thrift/protocol/TMultiplexedProtocol.cpp"
    "${library_root}/src/thrift/protocol/TProtocol.cpp"
    "${library_root}/src/thrift/server/TConnectedClient.cpp"
    "${library_root}/src/thrift/server/TServerFramework.cpp"
    "${library_root}/src/thrift/server/TSimpleServer.cpp"
    "${library_root}/src/thrift/server/TThreadedServer.cpp"
    "${library_root}/src/thrift/server/TThreadPoolServer.cpp"
    "${library_root}/src/thrift/TApplicationException.cpp"
    "${library_root}/src/thrift/TOutput.cpp"
    "${library_root}/src/thrift/transport/SocketCommon.cpp"
    "${library_root}/src/thrift/transport/TBufferTransports.cpp"
    "${library_root}/src/thrift/transport/TFDTransport.cpp"
    "${library_root}/src/thrift/transport/TFileTransport.cpp"
    "${library_root}/src/thrift/transport/THttpClient.cpp"
    "${library_root}/src/thrift/transport/THttpServer.cpp"
    "${library_root}/src/thrift/transport/THttpTransport.cpp"
    "${library_root}/src/thrift/transport/TPipe.cpp"
    "${library_root}/src/thrift/transport/TPipeServer.cpp"
    "${library_root}/src/thrift/transport/TServerSocket.cpp"
    "${library_root}/src/thrift/transport/TSimpleFileTransport.cpp"
    "${library_root}/src/thrift/transport/TSocket.cpp"
    "${library_root}/src/thrift/transport/TSocketPool.cpp"
    "${library_root}/src/thrift/transport/TSSLServerSocket.cpp"
    "${library_root}/src/thrift/transport/TSSLSocket.cpp"
    "${library_root}/src/thrift/transport/TTransportException.cpp"
    "${library_root}/src/thrift/transport/TTransportUtils.cpp"
    "${library_root}/src/thrift/transport/TWebSocketServer.cpp"
    "${library_root}/src/thrift/transport/TWebSocketServer.h"
  )

  if(PLATFORM_POSIX)
    set(tsocket_pool_compile_options "-include;random_shuffle.h")

  elseif(PLATFORM_WINDOWS)
    set(tsocket_pool_compile_options "/FIrandom_shuffle.h")
  endif()

  set_source_files_properties("${library_root}/src/thrift/transport/TSocketPool.cpp" PROPERTIES
    COMPILE_OPTIONS
      "${tsocket_pool_compile_options}"
  )

  if(PLATFORM_WINDOWS)
    target_sources(thirdparty_thrift_thrift PRIVATE
      "${library_root}/src/thrift/windows/GetTimeOfDay.cpp"
      "${library_root}/src/thrift/windows/OverlappedSubmissionThread.cpp"
      "${library_root}/src/thrift/windows/SocketPair.cpp"
      "${library_root}/src/thrift/windows/TWinsockSingleton.cpp"
      "${library_root}/src/thrift/windows/WinFcntl.cpp"
    )

  else()
    target_sources(thirdparty_thrift_thrift PRIVATE
      "${library_root}/src/thrift/VirtualProfiling.cpp"
      "${library_root}/src/thrift/server/TServer.cpp"
    )
  endif()

  target_include_directories(thirdparty_thrift_thrift PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/patches"
    "${library_root}/src"
    "${thrift_config_path}"
  )

  target_include_directories(thirdparty_thrift_thrift SYSTEM INTERFACE
    "${library_root}/src"
    "${thrift_config_path}"
  )

  target_link_libraries(thirdparty_thrift_thrift
    PRIVATE
      thirdparty_cxx_settings
      thirdparty_thrift_settings

    PUBLIC
      thirdparty_boost
      thirdparty_openssl
  )

  if(PLATFORM_POSIX)
    find_package(Threads REQUIRED)
    target_link_libraries(thirdparty_thrift_thrift PUBLIC
      Threads::Threads
    )

  elseif(PLATFORM_WINDOWS)
    target_link_libraries(thirdparty_thrift_thrift PUBLIC
      ws2_32
    )
  endif()

  add_library(thirdparty_thrift_thriftz
    "${library_root}/src/thrift/protocol/THeaderProtocol.cpp"
    "${library_root}/src/thrift/transport/THeaderTransport.cpp"
    "${library_root}/src/thrift/transport/TZlibTransport.cpp"
  )

  target_link_libraries(thirdparty_thrift_thriftz
    PRIVATE
      thirdparty_cxx_settings
      thirdparty_thrift_settings

    PUBLIC
      thirdparty_thrift_thrift
      thirdparty_zlib
  )

  target_include_directories(thirdparty_thrift_thriftz PRIVATE
    "${library_root}/src"
  )

  add_library(thirdparty_thrift INTERFACE)
  target_link_libraries(thirdparty_thrift INTERFACE
    thirdparty_thrift_thrift
    thirdparty_thrift_thriftz
  )
endfunction()

thriftMain()

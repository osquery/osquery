# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(thrifMain)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src/lib/cpp")

  add_library(thirdparty_thrift
    # libthrift
    "${library_root}/src/thrift/TApplicationException.cpp"
    "${library_root}/src/thrift/TOutput.cpp"
    "${library_root}/src/thrift/async/TAsyncChannel.cpp"
    "${library_root}/src/thrift/async/TAsyncProtocolProcessor.cpp"
    "${library_root}/src/thrift/async/TConcurrentClientSyncInfo.h"
    "${library_root}/src/thrift/async/TConcurrentClientSyncInfo.cpp"
    "${library_root}/src/thrift/concurrency/ThreadManager.cpp"
    "${library_root}/src/thrift/concurrency/TimerManager.cpp"
    "${library_root}/src/thrift/concurrency/Util.cpp"
    "${library_root}/src/thrift/processor/PeekProcessor.cpp"
    "${library_root}/src/thrift/protocol/TBase64Utils.cpp"
    "${library_root}/src/thrift/protocol/TDebugProtocol.cpp"
    "${library_root}/src/thrift/protocol/TJSONProtocol.cpp"
    "${library_root}/src/thrift/protocol/TMultiplexedProtocol.cpp"
    "${library_root}/src/thrift/protocol/TProtocol.cpp"
    "${library_root}/src/thrift/transport/TTransportException.cpp"
    "${library_root}/src/thrift/transport/TFDTransport.cpp"
    "${library_root}/src/thrift/transport/TSimpleFileTransport.cpp"
    "${library_root}/src/thrift/transport/THttpTransport.cpp"
    "${library_root}/src/thrift/transport/THttpClient.cpp"
    "${library_root}/src/thrift/transport/THttpServer.cpp"
    "${library_root}/src/thrift/transport/TSocket.cpp"
    "${library_root}/src/thrift/transport/TSocketPool.cpp"
    "${library_root}/src/thrift/transport/TServerSocket.cpp"
    "${library_root}/src/thrift/transport/TTransportUtils.cpp"
    "${library_root}/src/thrift/transport/TBufferTransports.cpp"
    "${library_root}/src/thrift/server/TConnectedClient.cpp"
    "${library_root}/src/thrift/server/TServerFramework.cpp"
    "${library_root}/src/thrift/server/TSimpleServer.cpp"
    "${library_root}/src/thrift/server/TThreadPoolServer.cpp"
    "${library_root}/src/thrift/server/TThreadedServer.cpp"

    "${library_root}/src/thrift/transport/TPipe.cpp"
    "${library_root}/src/thrift/transport/TPipeServer.cpp"
    "${library_root}/src/thrift/transport/TFileTransport.cpp"

    "${library_root}/src/thrift/transport/TSSLSocket.cpp"
    "${library_root}/src/thrift/transport/TSSLServerSocket.cpp"

    # thrift zlib server
    "${library_root}/src/thrift/transport/TZlibTransport.cpp"
    "${library_root}/src/thrift/protocol/THeaderProtocol.cpp"
    "${library_root}/src/thrift/transport/THeaderTransport.cpp"
    "${library_root}/src/thrift/protocol/THeaderProtocol.cpp"
    "${library_root}/src/thrift/transport/THeaderTransport.cpp"
  )

  if(DEFINED PLATFORM_WINDOWS)
    target_sources(thirdparty_thrift PRIVATE
      "${library_root}/src/thrift/windows/TWinsockSingleton.cpp"
      "${library_root}/src/thrift/windows/SocketPair.cpp"
      "${library_root}/src/thrift/windows/GetTimeOfDay.cpp"
      "${library_root}/src/thrift/windows/WinFcntl.cpp"

      "${library_root}/src/thrift/windows/OverlappedSubmissionThread.cpp"
    )
  else()
    target_sources(thirdparty_thrift PRIVATE
      "${library_root}/src/thrift/VirtualProfiling.cpp"
      "${library_root}/src/thrift/server/TServer.cpp"
    )
  endif()

  if(DEFINED PLATFORM_POSIX)
    target_sources(thirdparty_thrift PRIVATE
      "${library_root}/src/thrift/concurrency/PosixThreadFactory.cpp"
      "${library_root}/src/thrift/concurrency/Mutex.cpp"
      "${library_root}/src/thrift/concurrency/Monitor.cpp"
    )
  else()
    target_sources(thirdparty_thrift PRIVATE
      "${library_root}/src/thrift/concurrency/StdThreadFactory.cpp"
      "${library_root}/src/thrift/concurrency/StdMutex.cpp"
      "${library_root}/src/thrift/concurrency/StdMonitor.cpp"
    )
  endif()

  target_compile_definitions(thirdparty_thrift PRIVATE
    THRIFT_STATIC_DEFINE
  )

  target_link_libraries(thirdparty_thrift PUBLIC
    thirdparty_openssl
    thirdparty_zlib
    thirdparty_boost
  )

  target_link_libraries(thirdparty_thrift PRIVATE
    thirdparty_cxx_settings
  )

  target_include_directories(thirdparty_thrift PRIVATE
    "${library_root}/src"
    "${CMAKE_CURRENT_SOURCE_DIR}/config"
  )

  target_include_directories(thirdparty_thrift SYSTEM INTERFACE
    "${library_root}/src"
    "${CMAKE_CURRENT_SOURCE_DIR}/config"
  )
endfunction()

thrifMain()

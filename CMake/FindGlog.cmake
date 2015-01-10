include(FindPackageHandleStandardArgs)

set(GLOG_ROOT_DIR "${CMAKE_BINARY_DIR}/third-party/glog")
set(GLOG_SOURCE_DIR "${CMAKE_SOURCE_DIR}/third-party/glog")

if(NOT APPLE)
  include(CheckIncludeFiles)
  unset(LIBUNWIND_FOUND CACHE)
  check_include_files("libunwind.h;unwind.h" LIBUNWIND_FOUND)
  if(LIBUNWIND_FOUND)
    unset(libglog_FOUND CACHE)
    execute_process(
      COMMAND rm -rf "${GLOG_ROOT_DIR}" "${CMAKE_BINARY_DIR}/libglog-prefix"
      ERROR_QUIET
    )
    message(WARNING "${Esc}[31mWarning: libunwind headers found [Bug:596], please: make deps\n${Esc}[m")
  endif()
endif()

INCLUDE(ExternalProject)
ExternalProject_Add(
  libglog
  SOURCE_DIR ${GLOG_SOURCE_DIR}
  INSTALL_DIR ${GLOG_ROOT_DIR}
  UPDATE_COMMAND ${CMAKE_SOURCE_DIR}/tools/provision.sh
  CONFIGURE_COMMAND CC=/usr/bin/gcc CXX=/usr/bin/g++ ${GLOG_SOURCE_DIR}/configure --enable-frame-pointers --prefix=${GLOG_ROOT_DIR}
  BUILD_COMMAND make
  INSTALL_COMMAND make install
)

set(GLOG_INCLUDE_DIR "${GLOG_ROOT_DIR}/include")
set(GLOG_INCLUDE_DIRS ${GLOG_INCLUDE_DIR})

set(GLOG_LIBRARY "${GLOG_ROOT_DIR}/lib/libglog.a")
set(GLOG_LIBRARIES ${GLOG_LIBRARY})

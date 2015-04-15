include(FindPackageHandleStandardArgs)
if(POLICY CMP0054)
  cmake_policy(SET CMP0054 NEW)
endif()

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
    message(WARNING "${Esc}[31mWarning: libunwind headers found [Issue #596], please: make deps\n${Esc}[m")
  endif()
endif()

set(GLOG_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-deprecated-register -Wno-unnamed-type-template-args -Wno-deprecated -Wno-error")

INCLUDE(ExternalProject)
ExternalProject_Add(
  libglog
  SOURCE_DIR ${GLOG_SOURCE_DIR}
  INSTALL_DIR ${GLOG_ROOT_DIR}
  CONFIGURE_COMMAND ${GLOG_SOURCE_DIR}/configure
    CC=${CMAKE_C_COMPILER} CXX=${CMAKE_CXX_COMPILER}
    CXXFLAGS=${GLOG_CXX_FLAGS}
    --enable-frame-pointers --enable-shared=no --prefix=${GLOG_ROOT_DIR}
  BUILD_COMMAND make
  INSTALL_COMMAND make install
  LOG_CONFIGURE ON
  LOG_INSTALL ON
  LOG_BUILD ON
)

set(GLOG_INCLUDE_DIR "${GLOG_ROOT_DIR}/include")
set(GLOG_INCLUDE_DIRS ${GLOG_INCLUDE_DIR})

set(GLOG_LIBRARY "${GLOG_ROOT_DIR}/lib/libglog.a")
set(GLOG_LIBRARIES ${GLOG_LIBRARY})

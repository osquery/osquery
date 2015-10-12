include(FindPackageHandleStandardArgs)
if(POLICY CMP0054)
  cmake_policy(SET CMP0054 NEW)
endif()

set(GLOG_ROOT_DIR "${CMAKE_BINARY_DIR}/third-party/glog")
set(GLOG_SOURCE_DIR "${CMAKE_SOURCE_DIR}/third-party/glog")

set(GLOG_C_FLAGS "${CMAKE_C_FLAGS} ${C_COMPILE_FLAGS}")
if(APPLE)
  set(GLOG_C_FLAGS "${GLOG_C_FLAGS} -mmacosx-version-min=${APPLE_MIN_ABI}")
endif()
set(GLOG_CXX_FLAGS "${GLOG_C_FLAGS} ${CMAKE_CXX_FLAGS} ${CXX_COMPILE_FLAGS}")
set(GLOG_CXX_FLAGS "${GLOG_CXX_FLAGS} -Wno-deprecated-register -Wno-unnamed-type-template-args -Wno-deprecated -Wno-error")

set(GLOG_INCLUDE_DIR "${GLOG_ROOT_DIR}/include")
set(GLOG_INCLUDE_DIRS ${GLOG_INCLUDE_DIR})

set(GLOG_LIBRARY "${GLOG_ROOT_DIR}/lib/libglog.a")
set(GLOG_LIBRARIES ${GLOG_LIBRARY})

INCLUDE(ExternalProject)
ExternalProject_Add(
  libglog
  SOURCE_DIR ${GLOG_SOURCE_DIR}
  INSTALL_DIR ${GLOG_ROOT_DIR}
  CONFIGURE_COMMAND ${GLOG_SOURCE_DIR}/configure
    CC=${CMAKE_C_COMPILER} CXX=${CMAKE_CXX_COMPILER}
    CFLAGS=${GLOG_C_FLAGS} CXXFLAGS=${GLOG_CXX_FLAGS}
    --enable-frame-pointers --enable-shared=no --prefix=${GLOG_ROOT_DIR}
  BUILD_COMMAND ${CMAKE_MAKE_PROGRAM}
  INSTALL_COMMAND ${CMAKE_MAKE_PROGRAM} install
  LOG_CONFIGURE ON
  LOG_INSTALL ON
  LOG_BUILD ON
)

LOG_LIBRARY(glog "${GLOG_LIBRARY}")

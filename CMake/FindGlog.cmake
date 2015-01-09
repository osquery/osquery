include(FindPackageHandleStandardArgs)

set(GLOG_ROOT_DIR "${CMAKE_BINARY_DIR}/third-party/glog")
set(GLOG_SOURCE_DIR "${CMAKE_SOURCE_DIR}/third-party/glog")

INCLUDE(ExternalProject)
ExternalProject_Add(
  libglog
  SOURCE_DIR ${GLOG_SOURCE_DIR}
  CONFIGURE_COMMAND ${GLOG_SOURCE_DIR}/configure --enable-frame-pointers --prefix=${GLOG_ROOT_DIR}
  BUILD_COMMAND make
  INSTALL_COMMAND make install
  BUILD_IN_SOURCE 1
)

set(GLOG_INCLUDE_DIR "${GLOG_ROOT_DIR}/include")
set(GLOG_INCLUDE_DIRS ${GLOG_INCLUDE_DIR})

set(GLOG_LIBRARY "${GLOG_ROOT_DIR}/lib/libglog.a")
set(GLOG_LIBRARIES ${GLOG_LIBRARY})

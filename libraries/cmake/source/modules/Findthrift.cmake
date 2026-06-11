# FreeBSD: use system thrift from devel/thrift-cpp
include("${CMAKE_CURRENT_LIST_DIR}/freebsd_system_libs.cmake")
freebsd_use_system_lib(thrift
  LIBS thrift
  INCLUDES /usr/local/include
)

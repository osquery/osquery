# FreeBSD: use system gflags from devel/gflags
include("${CMAKE_CURRENT_LIST_DIR}/freebsd_system_libs.cmake")
freebsd_use_system_lib(gflags
  LIBS gflags
  INCLUDES /usr/local/include
)

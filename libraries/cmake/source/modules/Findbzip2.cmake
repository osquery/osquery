# FreeBSD: use base-system bzip2
include("${CMAKE_CURRENT_LIST_DIR}/freebsd_system_libs.cmake")
freebsd_use_system_lib(bzip2
  LIBS bz2
  INCLUDES /usr/include
)

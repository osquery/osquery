# FreeBSD: use base-system zlib
include("${CMAKE_CURRENT_LIST_DIR}/freebsd_system_libs.cmake")
freebsd_use_system_lib(zlib
  LIBS z
  INCLUDES /usr/include
)

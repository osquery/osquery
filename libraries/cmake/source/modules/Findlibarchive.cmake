# FreeBSD: use base-system libarchive
include("${CMAKE_CURRENT_LIST_DIR}/freebsd_system_libs.cmake")
freebsd_use_system_lib(libarchive
  LIBS archive
  INCLUDES /usr/include
)

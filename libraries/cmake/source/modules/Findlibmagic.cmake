# FreeBSD: use base-system libmagic
include("${CMAKE_CURRENT_LIST_DIR}/freebsd_system_libs.cmake")
freebsd_use_system_lib(libmagic
  LIBS magic
  INCLUDES /usr/include
)

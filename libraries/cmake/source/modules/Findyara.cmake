# FreeBSD: use system yara from security/yara
include("${CMAKE_CURRENT_LIST_DIR}/freebsd_system_libs.cmake")
freebsd_use_system_lib(yara
  LIBS yara
  INCLUDES /usr/local/include
)

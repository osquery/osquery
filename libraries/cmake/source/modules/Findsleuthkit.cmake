# FreeBSD: use system sleuthkit from sysutils/sleuthkit
include("${CMAKE_CURRENT_LIST_DIR}/freebsd_system_libs.cmake")
freebsd_use_system_lib(sleuthkit
  LIBS tsk
  INCLUDES /usr/local/include
)

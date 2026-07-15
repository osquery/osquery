# FreeBSD: use system augeas from textproc/augeas
# augeas.h pulls in libxml2 headers, which live under /usr/local/include/libxml2
include("${CMAKE_CURRENT_LIST_DIR}/freebsd_system_libs.cmake")
freebsd_use_system_lib(augeas
  LIBS augeas xml2
  INCLUDES /usr/local/include /usr/local/include/libxml2
)

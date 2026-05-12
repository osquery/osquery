# FreeBSD: use system liblz4 from archivers/liblz4
include("${CMAKE_CURRENT_LIST_DIR}/freebsd_system_libs.cmake")
freebsd_use_system_lib(lz4
  LIBS lz4
  INCLUDES /usr/local/include
)

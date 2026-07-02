# FreeBSD: use system zstd from archivers/zstd (also in base)
include("${CMAKE_CURRENT_LIST_DIR}/freebsd_system_libs.cmake")
freebsd_use_system_lib(zstd
  LIBS zstd
  INCLUDES /usr/local/include
)

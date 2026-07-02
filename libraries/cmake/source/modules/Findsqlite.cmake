# FreeBSD: use system sqlite from databases/sqlite3
include("${CMAKE_CURRENT_LIST_DIR}/freebsd_system_libs.cmake")
freebsd_use_system_lib(sqlite
  LIBS sqlite3
  INCLUDES /usr/local/include
)

# FreeBSD: header-only, use devel/rapidjson
include("${CMAKE_CURRENT_LIST_DIR}/freebsd_system_libs.cmake")
freebsd_use_system_lib(rapidjson
  INCLUDES /usr/local/include
)

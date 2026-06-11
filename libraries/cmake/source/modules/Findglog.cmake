# FreeBSD: use system glog from devel/glog
include("${CMAKE_CURRENT_LIST_DIR}/freebsd_system_libs.cmake")
freebsd_use_system_lib(glog
  LIBS glog
  INCLUDES /usr/local/include
  DEFINITIONS
    GLOG_USE_GLOG_EXPORT
    GOOGLE_GLOG_DLL_DECL=
    GLOG_NO_SYMBOLIZE_DETECTION
    GLOG_CUSTOM_PREFIX_SUPPORT
)

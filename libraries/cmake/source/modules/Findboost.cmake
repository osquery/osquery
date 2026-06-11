# FreeBSD: use system boost from devel/boost-libs
include("${CMAKE_CURRENT_LIST_DIR}/freebsd_system_libs.cmake")
freebsd_use_system_lib(boost
  LIBS
    boost_filesystem
    boost_thread
    boost_locale
    boost_atomic
    boost_chrono
    boost_container
    boost_random
    boost_context
    boost_coroutine
    boost_serialization
    boost_date_time
    boost_regex
    boost_program_options
    boost_iostreams
  INCLUDES /usr/local/include
)

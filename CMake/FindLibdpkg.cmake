# - Find libdpkg
# This module defines
# LIBPKG_VERSION, string representation of libpkg version
# LIBPKG_VERSION_MAJOR, major version number
# LIBPKG_VERSION_MINOR, minor version number
# LIBPKG_VERSION_PATCH, patch version number
# LIBPKG_VERSION_NUMBER, version as a compariable integer

find_package(PkgConfig QUIET)
pkg_check_modules(PC_LIBDPKG QUIET libdpkg)

set(LIBDPKG_VERSION ${PC_LIBDPKG_VERSION})
string(REGEX REPLACE "([0-9]+).[0-9]+.[0-9]+.*" "\\1" LIBDPKG_VERSION_MAJOR ${LIBDPKG_VERSION})
string(REGEX REPLACE "[0-9]+.([0-9]+).[0-9]+.*" "\\1" LIBDPKG_VERSION_MINOR ${LIBDPKG_VERSION})
string(REGEX REPLACE "[0-9]+.[0-9]+.([0-9]+).*" "\\1" LIBDPKG_VERSION_PATCH ${LIBDPKG_VERSION})
math(EXPR LIBDPKG_VERSION_NUMBER "${LIBDPKG_VERSION_MAJOR} * 1000000 + ${LIBDPKG_VERSION_MINOR} * 1000 + ${LIBDPKG_VERSION_PATCH}")

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Libdpkg DEFAULT_MSG LIBDPKG_VERSION)

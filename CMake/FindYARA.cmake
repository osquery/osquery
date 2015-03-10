# - Find the YARA library
# This module defines
#  YARA_INCLUDE_DIR, path to yara.h, etc.
#  YARA_LIBRARIES, the libraries required to use YARA.
#  YARA_FOUND, If false, do not try to use YARA.
# also defined, but not for general use are
# YARA_LIBRARY, where to find the YARA library.

# Apple readline does not support readline hooks
# So we look for another one by default
IF(APPLE)
  FIND_PATH(YARA_INCLUDE_DIR NAMES yara.h PATHS
    /sw/include
    /opt/local/include
    /opt/include
    /usr/local/include
    /usr/include/
    NO_DEFAULT_PATH)
ENDIF(APPLE)
FIND_PATH(YARA_INCLUDE_DIR NAMES yara.h)

IF(APPLE)
  FIND_LIBRARY(YARA_LIBRARY NAMES yara PATHS
    /sw/lib
    /opt/local/lib
    /opt/lib
    /usr/local/lib
    /usr/lib
    NO_DEFAULT_PATH
    )
ENDIF(APPLE)
FIND_LIBRARY(YARA_LIBRARY NAMES yara)

MARK_AS_ADVANCED(
  YARA_INCLUDE_DIR
  YARA_LIBRARY)

SET(YARA_FOUND "NO")
IF(YARA_INCLUDE_DIR)
  SET(YARA_FOUND "YES")
  SET(YARA_LIBRARIES)

ENDIF(YARA_INCLUDE_DIR)

IF(YARA_FOUND)
  MESSAGE(STATUS "Found YARA library")
ELSE(YARA_FOUND)
  IF(YARA_FIND_REQUIRED)
    MESSAGE(FATAL_ERROR "Could not find YARA -- please give some paths to CMake")
  ENDIF(YARA_FIND_REQUIRED)
ENDIF(YARA_FOUND)

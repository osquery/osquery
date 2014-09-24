# This code is released under the
# Apache License Version 2.0 http://www.apache.org/licenses/.
#
# Copyright (c) 2012 Louis Dionne
#
# Find snappy compression library and includes. This module defines:
#   snappy_INCLUDE_DIRS - The directories containing snappy's headers.
#   snappy_LIBRARIES    - A list of snappy's libraries.
#   snappy_FOUND        - Whether snappy was found.
#
# This module can be controlled by setting the following variables:
#   snappy_ROOT - The root directory where to find snappy. If this is not
#                 set, the default paths are searched.

if(NOT snappy_ROOT)
    find_path(snappy_INCLUDE_DIRS snappy.h)
    find_library(snappy_LIBRARIES NAMES snappy)
else()
    find_path(snappy_INCLUDE_DIRS snappy.h NO_DEFAULT_PATH PATHS ${snappy_ROOT})
    find_library(snappy_LIBRARIES NAMES snappy NO_DEFAULT_PATH PATHS ${snappy_ROOT})
endif()

if(snappy_INCLUDE_DIRS AND snappy_LIBRARIES)
    set(snappy_FOUND TRUE)
else()
    set(snappy_FOUND FALSE)
    set(snappy_INCLUDE_DIR)
    set(snappy_LIBRARIES)
endif()

mark_as_advanced(snappy_LIBRARIES snappy_INCLUDE_DIRS)

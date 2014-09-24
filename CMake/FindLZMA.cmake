# - Find lzma and lzmadec
# Find the native LZMA includes and library
#
#  LZMA_INCLUDE_DIR    - where to find lzma.h, etc.
#  LZMA_LIBRARIES      - List of libraries when using liblzma.
#  LZMA_FOUND          - True if liblzma found.
#  LZMADEC_INCLUDE_DIR - where to find lzmadec.h, etc.
#  LZMADEC_LIBRARIES   - List of libraries when using liblzmadec.
#  LZMADEC_FOUND       - True if liblzmadec found.

IF (LZMA_INCLUDE_DIR)
  # Already in cache, be silent
  SET(LZMA_FIND_QUIETLY TRUE)
ENDIF (LZMA_INCLUDE_DIR)

FIND_PATH(LZMA_INCLUDE_DIR lzma.h)
FIND_LIBRARY(LZMA_LIBRARY NAMES lzma )

# handle the QUIETLY and REQUIRED arguments and set LZMA_FOUND to TRUE if
# all listed variables are TRUE
INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(LZMA DEFAULT_MSG LZMA_LIBRARY LZMA_INCLUDE_DIR)

IF(LZMA_FOUND)
  SET( LZMA_LIBRARIES ${LZMA_LIBRARY} )
ELSE(LZMA_FOUND)
  SET( LZMA_LIBRARIES )

  IF (LZMADEC_INCLUDE_DIR)
    # Already in cache, be silent
    SET(LZMADEC_FIND_QUIETLY TRUE)
  ENDIF (LZMADEC_INCLUDE_DIR)

  FIND_PATH(LZMADEC_INCLUDE_DIR lzmadec.h)
  FIND_LIBRARY(LZMADEC_LIBRARY NAMES lzmadec )

  # handle the QUIETLY and REQUIRED arguments and set LZMADEC_FOUND to TRUE if
  # all listed variables are TRUE
  INCLUDE(FindPackageHandleStandardArgs)
  FIND_PACKAGE_HANDLE_STANDARD_ARGS(LZMADEC DEFAULT_MSG LZMADEC_LIBRARY
    LZMADEC_INCLUDE_DIR)

  IF(LZMADEC_FOUND)
    SET( LZMADEC_LIBRARIES ${LZMADEC_LIBRARY} )
  ELSE(LZMADEC_FOUND)
    SET( LZMADEC_LIBRARIES )
  ENDIF(LZMADEC_FOUND)
ENDIF(LZMA_FOUND)

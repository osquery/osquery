# - Find the readline library
# This module defines
#  READLINE_INCLUDE_DIR, path to readline/readline.h, etc.
#  READLINE_LIBRARIES, the libraries required to use READLINE.
#  READLINE_FOUND, If false, do not try to use READLINE.
# also defined, but not for general use are
# READLINE_readline_LIBRARY, where to find the READLINE library.
# READLINE_ncurses_LIBRARY, where to find the ncurses library [might not be defined]

# Apple readline does not support readline hooks
# So we look for another one by default
IF(APPLE)
  FIND_PATH(READLINE_INCLUDE_DIR NAMES readline/readline.h PATHS
    /sw/include
    /opt/local/include
    /opt/include
    /usr/local/include
    /usr/include/
    NO_DEFAULT_PATH
    )
ENDIF(APPLE)
FIND_PATH(READLINE_INCLUDE_DIR NAMES readline/readline.h)


# Apple readline does not support readline hooks
# So we look for another one by default
IF(APPLE)
  FIND_LIBRARY(READLINE_readline_LIBRARY NAMES readline PATHS
    /sw/lib
    /opt/local/lib
    /opt/lib
    /usr/local/lib
    /usr/lib
    NO_DEFAULT_PATH
    )
ENDIF(APPLE)
FIND_LIBRARY(READLINE_readline_LIBRARY NAMES readline)

# Sometimes readline really needs ncurses
IF(APPLE)
  FIND_LIBRARY(READLINE_ncurses_LIBRARY NAMES ncurses PATHS
    /sw/lib
    /opt/local/lib
    /opt/lib
    /usr/local/lib
    /usr/lib
    NO_DEFAULT_PATH
    )
ENDIF(APPLE)
FIND_LIBRARY(READLINE_ncurses_LIBRARY NAMES ncurses)

MARK_AS_ADVANCED(
  READLINE_INCLUDE_DIR
  READLINE_readline_LIBRARY
  READLINE_ncurses_LIBRARY
  )

SET( READLINE_FOUND "NO" )
IF(READLINE_INCLUDE_DIR)
  IF(READLINE_readline_LIBRARY)
    SET( READLINE_FOUND "YES" )
    SET( READLINE_LIBRARIES
      ${READLINE_readline_LIBRARY}
      )
    LOG_LIBRARY(readline "${READLINE_readline_LIBRARY}")

    # some readline libraries depend on ncurses
    IF(READLINE_ncurses_LIBRARY)
      SET(READLINE_LIBRARIES ${READLINE_LIBRARIES} ${READLINE_ncurses_LIBRARY})
      LOG_LIBRARY(ncurses "${READLINE_ncurses_LIBRARY}")
    ENDIF(READLINE_ncurses_LIBRARY)

  ENDIF(READLINE_readline_LIBRARY)
ENDIF(READLINE_INCLUDE_DIR)

IF(NOT READLINE_FOUND)
  IF(READLINE_FIND_REQUIRED)
    MESSAGE(FATAL_ERROR "Could not find readline -- please give some paths to CMake")
  ENDIF(READLINE_FIND_REQUIRED)
ENDIF(NOT READLINE_FOUND)

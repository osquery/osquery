# - Try to find Broker headers and libraries.
#
# Usage of this module as follows:
#
#     find_package(Broker)
#
# Variables used by this module, they can change the default behaviour and need
# to be set before calling find_package:
#
#  BROKER_ROOT_DIR   Set this variable to the root installation of
#                    Broker if the module has problems finding
#                    the proper installation path.
#
# Variables defined by this module:
#
#  BROKER_FOUND             System has Broker libs/headers
#  BROKER_LIBRARY           The Broker library/libraries
#  BROKER_INCLUDE_DIR       The location of Broker headers

find_path(BROKER_ROOT_DIR
    NAMES include/broker/broker.hh broker/broker.hh
)

find_library(BROKER_LIBRARY
    NAMES broker
    HINTS ${BROKER_ROOT_DIR}/build ${BROKER_ROOT_DIR}/lib
)

find_path(BROKER_INCLUDE_DIR
    NAMES broker/broker.hh
    HINTS ${BROKER_ROOT_DIR}/ ${BROKER_ROOT_DIR}/include
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Broker DEFAULT_MSG
    BROKER_LIBRARY
    BROKER_INCLUDE_DIR
)

mark_as_advanced(
    BROKER_ROOT
    BROKER_LIBRARY
    BROKER_INCLUDE_DIR
)

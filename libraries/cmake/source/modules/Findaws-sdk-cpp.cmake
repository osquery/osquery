# FreeBSD: use system aws-sdk-cpp from devel/aws-sdk-cpp
#
# osquery's downstream CMake files link against per-service targets like
# thirdparty_aws-cpp-sdk-ec2, thirdparty_aws-cpp-sdk-sts, etc., plus an
# umbrella thirdparty_aws-sdk-cpp.  Create all of them as INTERFACE
# targets wrapping system shared libraries.  Each system lib is wrapped
# in an IMPORTED target so osquery's add_real_target_dependencies() walker
# (which calls get_target_property TYPE on each INTERFACE_LINK_LIBRARIES
# entry) sees a real target, not an absolute path.

set(_aws_services
  core
  ec2
  sts
  kinesis
  firehose
)

set(_aws_link_targets)
foreach(svc ${_aws_services})
  find_library(_aws_${svc}_LIB aws-cpp-sdk-${svc} REQUIRED)
  set(_imp_target thirdparty_aws-cpp-sdk-${svc}_imp)
  if(NOT TARGET ${_imp_target})
    add_library(${_imp_target} SHARED IMPORTED GLOBAL)
    set_target_properties(${_imp_target} PROPERTIES
      IMPORTED_LOCATION "${_aws_${svc}_LIB}"
    )
  endif()
  if(NOT TARGET thirdparty_aws-cpp-sdk-${svc})
    add_library(thirdparty_aws-cpp-sdk-${svc} INTERFACE)
    target_link_libraries(thirdparty_aws-cpp-sdk-${svc} INTERFACE ${_imp_target})
    target_include_directories(thirdparty_aws-cpp-sdk-${svc} SYSTEM INTERFACE /usr/local/include)
  endif()
  list(APPEND _aws_link_targets thirdparty_aws-cpp-sdk-${svc})
endforeach()

if(NOT TARGET thirdparty_aws-sdk-cpp)
  add_library(thirdparty_aws-sdk-cpp INTERFACE)
  target_link_libraries(thirdparty_aws-sdk-cpp INTERFACE ${_aws_link_targets})
endif()

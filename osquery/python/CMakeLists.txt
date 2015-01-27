find_package(PythonLibs 2.7 REQUIRED)
include_directories(${PYTHON_INCLUDE_DIRS})

find_package(Boost COMPONENTS python REQUIRED)
include_directories(${Boost_INCLUDE_DIR})

add_library(pyosquery SHARED "pyosquery.cpp")
target_link_libraries(pyosquery libosquery_basic)
target_link_libraries(pyosquery "boost_python")
target_link_libraries(pyosquery "python")
set_target_properties(pyosquery PROPERTIES PREFIX "")
set_target_properties(pyosquery PROPERTIES SUFFIX ".so")

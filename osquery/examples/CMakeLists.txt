include(${CMAKE_SOURCE_DIR}/external/cmake/cmakelibs.cmake)

function(osqueryExtensionsExampleMain)
    addOsqueryExtension(example_extension example_extension.cpp)
    target_link_libraries(example_extension PRIVATE
        osquery_sdk_pluginsdk
        osquery_extensions_implthrift
    )
endfunction()

osqueryExtensionsExampleMain()

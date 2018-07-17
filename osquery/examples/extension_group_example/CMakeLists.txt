project(ext_example)

function(main)
  set(PROJECT_SOURCEFILES
    "${CMAKE_CURRENT_SOURCE_DIR}/src/example.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/example.cpp"
  )

  add_osquery_extension_ex("ExampleTable" "table" "example"
    SOURCES ${PROJECT_SOURCEFILES}
    INCLUDEDIRS "${CMAKE_CURRENT_SOURCE_DIR}/src"
    MAININCLUDES "example.h"
  )
endfunction()

main()

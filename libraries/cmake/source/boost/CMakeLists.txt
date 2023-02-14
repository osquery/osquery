# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(boostMain)
  set(BOOST_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/src")

  importBoostInterfaceLibraries()

  generateBoostSerialization()
  generateBoostAtomic()
  generateBoostChrono()
  generateBoostContainer()
  generateBoostRandom()
  generateBoostThread()
  generateBoostLocale()
  generateBoostFilesystem()
  generateBoostContext()

  add_library(thirdparty_boost INTERFACE)
  target_link_libraries(thirdparty_boost INTERFACE
    thirdparty_boost_numeric_conversion
    thirdparty_boost_locale
    thirdparty_boost_algorithm
    thirdparty_boost_variant
    thirdparty_boost_filesystem
    thirdparty_boost_coroutine2
    thirdparty_boost_context
    thirdparty_boost_asio
    thirdparty_boost_beast
    thirdparty_boost_format
    thirdparty_boost_io
    thirdparty_boost_property_tree
    thirdparty_boost_uuid
    thirdparty_boost_scope_exit
    thirdparty_boost_circular_buffer
  )
endfunction()

function(importBoostInterfaceLibrary folder_name)
  set(library_root "${BOOST_ROOT}/libs/${folder_name}")

  string(REPLACE "/" "_" target_name "${folder_name}")
  set(target_name "thirdparty_boost_${target_name}")

  add_library("${target_name}" INTERFACE)
  target_include_directories("${target_name}" SYSTEM INTERFACE
    "${library_root}/include"
  )

  foreach(additional_dependency ${ARGN})
    if(additional_dependency MATCHES "^thirdparty_")
      target_link_libraries("${target_name}" INTERFACE
        "${additional_dependency}"
      )

    else()
      target_link_libraries("${target_name}" INTERFACE
        "thirdparty_boost_${additional_dependency}"
      )
    endif()
  endforeach()
endfunction()

function(importBoostInterfaceLibraries)
  set(library_descriptor_list
    "config:"
    "throw_exception:assert,config"
    "static_assert:config"
    "core:assert,config"
    "assert:config"
    "array:assert,config,core,static_assert,throw_exception"
    "bind:config,core"
    "preprocessor:"
    "type_traits:config,static_assert"
    "concept_check:config,preprocessor,static_assert,type_traits"
    "move:assert,config,core,static_assert"
    "smart_ptr:assert,config,core,move,static_assert,throw_exception,type_traits"
    "tuple:config,core,static_assert,type_traits"
    "exception:assert,config,core,smart_ptr,throw_exception,tuple,type_traits"
    "integer:assert,config,core,static_assert,throw_exception"
    "detail:config,core,preprocessor,static_assert,type_traits"
    "container_hash:assert,config,core,detail,integer,static_assert,type_traits"
    "type_index:config,container_hash,core,preprocessor,smart_ptr,static_assert,throw_exception,type_traits"
    "typeof:config,preprocessor,type_traits"
    "function:assert,bind,config,core,integer,preprocessor,throw_exception,type_index,type_traits,typeof"
    "function_types:config,core,detail,mpl,preprocessor,type_traits"
    "fusion:config,container_hash,core,function_types,mpl,preprocessor,static_assert,tuple,type_traits,typeof,utility"
    "optional:assert,config,core,detail,move,predef,static_assert,throw_exception,type_traits,utility"
    "iterator:assert,concept_check,config,conversion,core,detail,function_types,fusion,mpl,optional,smart_ptr,static_assert,type_traits,utility"
    "predef:"
    "mpl:config,core,predef,preprocessor,static_assert,type_traits,utility"
    "range:array,assert,concept_check,config,container_hash,conversion,core,detail,iterator,mpl,optional,preprocessor,regex,static_assert,tuple,type_traits,utility"
    "regex:config,throw_exception,predef,assert"
    "unordered:assert,config,container,container_hash,core,detail,move,predef,preprocessor,smart_ptr,throw_exception,tuple,type_traits"
    "algorithm:array,assert,bind,concept_check,config,core,exception,function,iterator,mpl,range,regex,static_assert,throw_exception,tuple,type_traits,unordered"
    "io:config"
    "lexical_cast:array,assert,config,container,core,integer,numeric_conversion,range,static_assert,throw_exception,type_traits"
    "conversion:assert,config,core,smart_ptr,throw_exception,type_traits,typeof"
    "numeric/conversion:config,conversion,core,mpl,preprocessor,throw_exception,type_traits"
    "tokenizer:assert,config,iterator,mpl,throw_exception,type_traits"
    "utility:config,core,io,preprocessor,static_assert,throw_exception,type_traits"
    "winapi:config,predef"
    "date_time:algorithm,assert,config,core,io,lexical_cast,numeric_conversion,range,smart_ptr,static_assert,throw_exception,tokenizer,type_traits,utility,winapi"
    "system:config,winapi"
    "intrusive:assert,config,container_hash,core,move,static_assert"
    "rational:assert,config,core,integer,static_assert,throw_exception,type_traits,utility"
    "ratio:config,core,integer,mpl,rational,static_assert,type_traits"
    "align:assert,config,core,static_assert"
    "variant:assert,bind,config,container_hash,core,detail,integer,move,mpl,preprocessor,static_assert,throw_exception,type_index,type_traits,utility"
    "endian:config,core,static_assert,type_traits"
    "phoenix:assert,bind,config,core,function,fusion,mpl,predef,preprocessor,proto,range,smart_ptr,type_traits,utility"
    "pool:assert,config,integer,throw_exception,type_traits,winapi"
    "proto:config,core,fusion,mpl,preprocessor,range,static_assert,type_traits,typeof,utility"
    "spirit:array,assert,config,core,endian,function,function_types,fusion,integer,io,iterator,move,mpl,optional,phoenix,pool,preprocessor,proto,range,regex,smart_ptr,static_assert,thread,throw_exception,type_traits,typeof,unordered,utility,variant"
    "coroutine2:assert,config,context"
    "asio:array,assert,bind,chrono,config,core,coroutine2,date_time,function,regex,smart_ptr,system,throw_exception,type_traits,utility"
    "beast:asio,assert,bind,config,container,core,endian,intrusive,logic,mp11,optional,smart_ptr,static_assert,system,throw_exception,type_traits,utility,winapi"
    "logic:config,core"
    "mp11:"
    "format:assert,config,core,optional,smart_ptr,throw_exception,utility"
    "property_tree:any,assert,bind,config,core,format,iterator,mpl,multi_index,optional,range,serialization,static_assert,throw_exception,type_traits"
    "any:config,core,static_assert,throw_exception,type_index,type_traits"
    "multi_index:assert,bind,config,container_hash,core,foreach,integer,iterator,move,mpl,preprocessor,serialization,smart_ptr,static_assert,throw_exception,tuple,type_traits,utility"
    "foreach:config,core,iterator,mpl,range,type_traits"
    "uuid:assert,config,container_hash,core,io,move,numeric_conversion,predef,random,serialization,static_assert,throw_exception,tti,type_traits,winapi"
    "tti:config,function_types,mpl,preprocessor,type_traits"
    "dynamic_bitset:assert,config,container_hash,core,integer,move,static_assert,throw_exception"
    "scope_exit:config,function,preprocessor,type_traits,typeof"
    "circular_buffer:assert,concept_check,config,core,move,static_assert,throw_exception,type_traits"
  )

  foreach(library_descriptor ${library_descriptor_list})
    string(REPLACE ":" ";" temp "${library_descriptor}")
    list(GET temp 0 library_name)
    list(GET temp 1 library_dependency_list)

    string(REPLACE "," ";" library_dependency_list "${library_dependency_list}")
    importBoostInterfaceLibrary("${library_name}" ${library_dependency_list})
  endforeach()

  # Additional settings for the libraries we just imported
  if(PLATFORM_LINUX)
    target_compile_definitions(thirdparty_boost_uuid INTERFACE
      BOOST_UUID_RANDOM_PROVIDER_FORCE_POSIX
    )
  endif()

  if(PLATFORM_WINDOWS)
    target_compile_definitions(thirdparty_boost_asio INTERFACE
      BOOST_ASIO_WINDOWS
    )

    target_compile_definitions(thirdparty_boost_winapi INTERFACE
      BOOST_USE_WINDOWS_H
      NOMINMAX
    )
  endif()
endfunction()

function(generateBoostSerialization)
  set(library_root "${BOOST_ROOT}/libs/serialization")

  add_library(thirdparty_boost_serialization STATIC EXCLUDE_FROM_ALL
    "${library_root}/src/archive_exception.cpp"
    "${library_root}/src/basic_archive.cpp"
    "${library_root}/src/basic_iarchive.cpp"
    "${library_root}/src/basic_iserializer.cpp"
    "${library_root}/src/basic_oarchive.cpp"
    "${library_root}/src/basic_oserializer.cpp"
    "${library_root}/src/basic_pointer_iserializer.cpp"
    "${library_root}/src/basic_pointer_oserializer.cpp"
    "${library_root}/src/basic_serializer_map.cpp"
    "${library_root}/src/basic_text_iprimitive.cpp"
    "${library_root}/src/basic_text_oprimitive.cpp"
    "${library_root}/src/basic_xml_archive.cpp"
    "${library_root}/src/binary_iarchive.cpp"
    "${library_root}/src/binary_oarchive.cpp"
    "${library_root}/src/extended_type_info.cpp"
    "${library_root}/src/extended_type_info_typeid.cpp"
    "${library_root}/src/extended_type_info_no_rtti.cpp"
    "${library_root}/src/polymorphic_iarchive.cpp"
    "${library_root}/src/polymorphic_oarchive.cpp"
    "${library_root}/src/stl_port.cpp"
    "${library_root}/src/text_iarchive.cpp"
    "${library_root}/src/text_oarchive.cpp"
    "${library_root}/src/polymorphic_text_iarchive.cpp"
    "${library_root}/src/polymorphic_text_oarchive.cpp"
    "${library_root}/src/polymorphic_binary_iarchive.cpp"
    "${library_root}/src/polymorphic_binary_oarchive.cpp"
    "${library_root}/src/polymorphic_xml_iarchive.cpp"
    "${library_root}/src/polymorphic_xml_oarchive.cpp"
    "${library_root}/src/void_cast.cpp"
    "${library_root}/src/xml_grammar.cpp"
    "${library_root}/src/xml_iarchive.cpp"
    "${library_root}/src/xml_archive_exception.cpp"
    "${library_root}/src/codecvt_null.cpp"
  )

  target_include_directories(thirdparty_boost_serialization PRIVATE
    "${library_root}/include"
  )

  target_include_directories(thirdparty_boost_serialization SYSTEM INTERFACE
    "${library_root}/include"
  )

  target_link_libraries(thirdparty_boost_serialization
    PRIVATE
      thirdparty_cxx_settings

    PUBLIC
      thirdparty_boost_array
      thirdparty_boost_assert
      thirdparty_boost_config
      thirdparty_boost_core
      thirdparty_boost_detail
      thirdparty_boost_integer
      thirdparty_boost_io
      thirdparty_boost_iterator
      thirdparty_boost_move
      thirdparty_boost_mpl
      thirdparty_boost_optional
      thirdparty_boost_predef
      thirdparty_boost_preprocessor
      thirdparty_boost_smart_ptr
      thirdparty_boost_spirit
      thirdparty_boost_static_assert
      thirdparty_boost_type_traits
      thirdparty_boost_unordered
      thirdparty_boost_utility
      thirdparty_boost_variant
      thirdparty_boost_function
  )

  add_library(thirdparty_boost_wserialization STATIC EXCLUDE_FROM_ALL
    "${library_root}/src/basic_text_wiprimitive.cpp"
    "${library_root}/src/basic_text_woprimitive.cpp"
    "${library_root}/src/text_wiarchive.cpp"
    "${library_root}/src/text_woarchive.cpp"
    "${library_root}/src/polymorphic_text_wiarchive.cpp"
    "${library_root}/src/polymorphic_text_woarchive.cpp"
    "${library_root}/src/xml_wgrammar.cpp"
    "${library_root}/src/xml_wiarchive.cpp"
    "${library_root}/src/xml_woarchive.cpp"
    "${library_root}/src/polymorphic_xml_wiarchive.cpp"
    "${library_root}/src/polymorphic_xml_woarchive.cpp"
  )

  target_include_directories(thirdparty_boost_wserialization PRIVATE
    "${library_root}/include"
  )

  target_include_directories(thirdparty_boost_wserialization SYSTEM INTERFACE
    "${library_root}/include"
  )

  target_link_libraries(thirdparty_boost_wserialization
    PRIVATE
      thirdparty_cxx_settings

    PUBLIC
      thirdparty_boost_serialization
      thirdparty_boost_array
  )
endfunction()

function(generateBoostAtomic)
  set(library_root "${BOOST_ROOT}/libs/atomic")

  add_library(thirdparty_boost_atomic STATIC EXCLUDE_FROM_ALL
    "${library_root}/src/lock_pool.cpp"
  )

  if(TARGET_PROCESSOR STREQUAL "x86_64)")
    set(sse2_src_file "${library_root}/src/find_address_sse2.cpp")
    set(sse41_src_file "${library_root}/src/find_address_sse41.cpp")

    target_sources(thirdparty_boost_atomic PRIVATE
      "${sse2_src_file}"
      "${sse41_src_file}"
    )

    if(PLATFORM_WINDOWS)
      set(sse2_flags "-msse -msse2")
      set(sse41_flags "-msse -msse2 -msse3 -mssse3 -msse4.1")

    elseif(PLATFORM_POSIX)
      set(sse2_flags "/arch:SSE2")
      set(sse41_flags "${sse2_flags}")
    endif()

    set_source_files_properties("${sse2_src_file}" PROPERTIES
      COMPILE_FLAGS
        "${boost_atomic_sse2_cflags}"
    )

    set_source_files_properties("${sse41_src_file}" PROPERTIES
      COMPILE_FLAGS
        "${boost_atomic_sse2_cflags}"
    )

    target_compile_definitions(thirdparty_boost_atomic PUBLIC
      BOOST_ATOMIC_USE_SSE2
      BOOST_ATOMIC_USE_SSE41
    )
  endif()

  target_include_directories(thirdparty_boost_atomic PRIVATE
    "${library_root}/src"
  )

  target_include_directories(thirdparty_boost_atomic SYSTEM PUBLIC
    "${library_root}/include"
  )

  target_compile_definitions(thirdparty_boost_atomic PUBLIC
    BOOST_ATOMIC_STATIC_LINK
    BOOST_ATOMIC_SOURCE
  )

  if(PLATFORM_POSIX)
    find_package(Threads REQUIRED)
    target_link_libraries(thirdparty_boost_atomic PUBLIC
      Threads::Threads
    )
  endif()

  if(PLATFORM_WINDOWS)
    target_sources(thirdparty_boost_atomic PRIVATE
      "${library_root}/src/wait_ops_windows.cpp"
    )

    target_compile_definitions(thirdparty_boost_atomic PUBLIC
      BOOST_USE_WINDOWS_H
    )

    target_link_libraries(thirdparty_boost_atomic PUBLIC
      thirdparty_boost_winapi
      synchronization
    )
  endif()

  target_link_libraries(thirdparty_boost_atomic
    PRIVATE
      thirdparty_cxx_settings

    PUBLIC
      thirdparty_boost_assert
      thirdparty_boost_config
      thirdparty_boost_static_assert
      thirdparty_boost_type_traits
      thirdparty_boost_align
      thirdparty_boost_predef
      thirdparty_boost_preprocessor
  )
endfunction()

function(generateBoostChrono)
  set(library_root "${BOOST_ROOT}/libs/chrono")

  add_library(thirdparty_boost_chrono STATIC EXCLUDE_FROM_ALL
    "${library_root}/src/chrono.cpp"
    "${library_root}/src/process_cpu_clocks.cpp"
    "${library_root}/src/thread_clock.cpp"
  )

  target_compile_definitions(thirdparty_boost_chrono PRIVATE
    BOOST_CHRONO_STATIC_LINK
    BOOST_All_STATIC_LINK
  )

  target_include_directories(thirdparty_boost_chrono PRIVATE
    "${library_root}/include"
  )

  target_include_directories(thirdparty_boost_chrono SYSTEM INTERFACE
    "${library_root}/include"
  )

  target_link_libraries(thirdparty_boost_chrono
    PRIVATE
      thirdparty_cxx_settings

    PUBLIC
      thirdparty_boost_assert
      thirdparty_boost_config
      thirdparty_boost_core
      thirdparty_boost_integer
      thirdparty_boost_move
      thirdparty_boost_mpl
      thirdparty_boost_predef
      thirdparty_boost_ratio
      thirdparty_boost_static_assert
      thirdparty_boost_system
      thirdparty_boost_throw_exception
      thirdparty_boost_type_traits
      thirdparty_boost_typeof
      thirdparty_boost_utility
      thirdparty_boost_winapi
  )
endfunction()

function(generateBoostContainer)
  set(library_root "${BOOST_ROOT}/libs/container")

  add_library(thirdparty_boost_container_alloc_lib OBJECT
    "${library_root}/src/alloc_lib.c"
  )

  target_link_libraries(thirdparty_boost_container_alloc_lib PRIVATE
    thirdparty_c_settings
  )

  target_include_directories(thirdparty_boost_container_alloc_lib PRIVATE
    "${library_root}/include"
  )

  add_library(thirdparty_boost_container STATIC EXCLUDE_FROM_ALL
    $<TARGET_OBJECTS:thirdparty_boost_container_alloc_lib>

    "${library_root}/src/dlmalloc.cpp"
    "${library_root}/src/global_resource.cpp"
    "${library_root}/src/monotonic_buffer_resource.cpp"
    "${library_root}/src/pool_resource.cpp"
    "${library_root}/src/synchronized_pool_resource.cpp"
    "${library_root}/src/unsynchronized_pool_resource.cpp"
  )

  target_compile_definitions(thirdparty_boost_container PRIVATE
    BOOST_CONTAINER_STATIC_LINK
  )

  target_include_directories(thirdparty_boost_container PRIVATE
    "${library_root}/include"
  )

  target_include_directories(thirdparty_boost_container SYSTEM INTERFACE
    "${library_root}/include"
  )

  target_link_libraries(thirdparty_boost_container
    PRIVATE
      thirdparty_cxx_settings

    PUBLIC
      thirdparty_boost_assert
      thirdparty_boost_config
      thirdparty_boost_core
      thirdparty_boost_intrusive
      thirdparty_boost_move
      thirdparty_boost_static_assert
      thirdparty_boost_type_traits
      thirdparty_boost_winapi
  )
endfunction()

function(generateBoostRandom)
  set(library_root "${BOOST_ROOT}/libs/random")

  add_library(thirdparty_boost_random STATIC EXCLUDE_FROM_ALL
    "${library_root}/src/random_device.cpp"
  )

  target_include_directories(thirdparty_boost_random SYSTEM PUBLIC
    "${library_root}/include"
  )

  target_link_libraries(thirdparty_boost_random
    PRIVATE
      thirdparty_cxx_settings

    PUBLIC
      thirdparty_boost_array
      thirdparty_boost_assert
      thirdparty_boost_config
      thirdparty_boost_core
      thirdparty_boost_dynamic_bitset
      thirdparty_boost_integer
      thirdparty_boost_io
      thirdparty_boost_range
      thirdparty_boost_static_assert
      thirdparty_boost_system
      thirdparty_boost_throw_exception
      thirdparty_boost_type_traits
      thirdparty_boost_utility
  )
endfunction()

function(generateBoostThread)
  set(library_root "${BOOST_ROOT}/libs/thread")

  add_library(thirdparty_boost_thread STATIC EXCLUDE_FROM_ALL
    "${library_root}/src/future.cpp"
  )

  if(DEFINED PLATFORM_POSIX)
    target_sources(thirdparty_boost_thread PRIVATE
      "${library_root}/src/pthread/thread.cpp"
      "${library_root}/src/pthread/once.cpp"
    )

    target_compile_definitions(thirdparty_boost_thread PRIVATE
      BOOST_THREAD_POSIX
      BOOST_THREAD_DONT_USE_CHRONO
    )

  elseif(DEFINED PLATFORM_WINDOWS)
    target_sources(thirdparty_boost_thread PRIVATE
      "${library_root}/src/win32/thread.cpp"
      "${library_root}/src/win32/tss_dll.cpp"
      "${library_root}/src/win32/tss_pe.cpp"
      "${library_root}/src/win32/thread_primitives.cpp"
    )

    target_compile_definitions(thirdparty_boost_thread PRIVATE
      BOOST_THREAD_WIN32
      WIN32_LEAN_AND_MEAN
      BOOST_USE_WINDOWS_H
      BOOST_THREAD_USES_CHRONO
    )
  endif()

  target_compile_definitions(thirdparty_boost_thread PRIVATE
    BOOST_THREAD_BUILD_LIB=1
  )

  target_include_directories(thirdparty_boost_thread SYSTEM PUBLIC
    "${library_root}/include"
  )

  target_link_libraries(thirdparty_boost_thread
    PRIVATE
      thirdparty_cxx_settings

    PUBLIC
      thirdparty_boost_assert
      thirdparty_boost_atomic
      thirdparty_boost_bind
      thirdparty_boost_chrono
      thirdparty_boost_concept_check
      thirdparty_boost_config
      thirdparty_boost_container
      thirdparty_boost_container_hash
      thirdparty_boost_core
      thirdparty_boost_date_time
      thirdparty_boost_exception
      thirdparty_boost_function
      thirdparty_boost_intrusive
      thirdparty_boost_io
      thirdparty_boost_iterator
      thirdparty_boost_move
      thirdparty_boost_optional
      thirdparty_boost_predef
      thirdparty_boost_preprocessor
      thirdparty_boost_smart_ptr
      thirdparty_boost_static_assert
      thirdparty_boost_system
      thirdparty_boost_throw_exception
      thirdparty_boost_tuple
      thirdparty_boost_type_traits
      thirdparty_boost_utility
      thirdparty_boost_winapi
      thirdparty_boost_algorithm
      thirdparty_boost_lexical_cast
  )

  if(PLATFORM_POSIX)
    find_package(Threads REQUIRED)
    target_link_libraries(thirdparty_boost_thread PUBLIC
      Threads::Threads
    )
  endif()
endfunction()

function(generateBoostLocale)
  set(library_root "${BOOST_ROOT}/libs/locale")

  add_library(thirdparty_boost_locale STATIC EXCLUDE_FROM_ALL
    "${library_root}/src/std/codecvt.cpp"
    "${library_root}/src/std/collate.cpp"
    "${library_root}/src/std/converter.cpp"
    "${library_root}/src/std/numeric.cpp"
    "${library_root}/src/std/std_backend.cpp"
    "${library_root}/src/util/gregorian.cpp"
    "${library_root}/src/encoding/codepage.cpp"
    "${library_root}/src/shared/date_time.cpp"
    "${library_root}/src/shared/format.cpp"
    "${library_root}/src/shared/formatting.cpp"
    "${library_root}/src/shared/generator.cpp"
    "${library_root}/src/shared/ids.cpp"
    "${library_root}/src/shared/localization_backend.cpp"
    "${library_root}/src/shared/message.cpp"
    "${library_root}/src/shared/mo_lambda.cpp"
    "${library_root}/src/util/codecvt_converter.cpp"
    "${library_root}/src/util/default_locale.cpp"
    "${library_root}/src/util/info.cpp"
    "${library_root}/src/util/locale_data.cpp"
  )

  if(DEFINED PLATFORM_POSIX)
    target_sources(thirdparty_boost_locale PRIVATE
      "${library_root}/src/posix/collate.cpp"
      "${library_root}/src/posix/converter.cpp"
      "${library_root}/src/posix/numeric.cpp"
      "${library_root}/src/posix/codecvt.cpp"
      "${library_root}/src/posix/posix_backend.cpp"
    )

    target_compile_definitions(thirdparty_boost_locale PRIVATE
      BOOST_LOCALE_WITH_ICONV=1
      BOOST_LOCALE_NO_WINAPI_BACKEND=1
    )

  elseif(DEFINED PLATFORM_WINDOWS)
    target_sources(thirdparty_boost_locale PRIVATE
      "${library_root}/src/win32/collate.cpp"
      "${library_root}/src/win32/converter.cpp"
      "${library_root}/src/win32/numeric.cpp"
      "${library_root}/src/win32/win_backend.cpp"
      "${library_root}/src/win32/lcid.cpp"
    )

    target_compile_definitions(thirdparty_boost_locale PRIVATE
      BOOST_LOCALE_NO_POSIX_BACKEND=1
    )
  endif()

  target_include_directories(thirdparty_boost_locale PRIVATE
    "${library_root}/src"
    "${library_root}/src/encoding"
    "${library_root}/src/icu"
    "${library_root}/src/shared"
    "${library_root}/src/std"
    "${library_root}/src/util"
  )

  target_include_directories(thirdparty_boost_locale SYSTEM PUBLIC
    "${library_root}/include"
  )

  target_link_libraries(thirdparty_boost_locale
    PRIVATE
      thirdparty_cxx_settings

    PUBLIC
      thirdparty_boost_assert
      thirdparty_boost_config
      thirdparty_boost_function
      thirdparty_boost_iterator
      thirdparty_boost_smart_ptr
      thirdparty_boost_static_assert
      thirdparty_boost_type_traits
      thirdparty_boost_thread
      thirdparty_boost_unordered
  )
endfunction()

function(generateBoostFilesystem)
  set(library_root "${BOOST_ROOT}/libs/filesystem")

  add_library(thirdparty_boost_filesystem STATIC EXCLUDE_FROM_ALL
    "${library_root}/src/codecvt_error_category.cpp"
    "${library_root}/src/exception.cpp"
    "${library_root}/src/operations.cpp"
    "${library_root}/src/directory.cpp"
    "${library_root}/src/path.cpp"
    "${library_root}/src/path_traits.cpp"
    "${library_root}/src/portability.cpp"
    "${library_root}/src/unique_path.cpp"
    "${library_root}/src/utf8_codecvt_facet.cpp"
  )

  target_include_directories(thirdparty_boost_filesystem SYSTEM PUBLIC
    "${library_root}/include"
  )

  target_link_libraries(thirdparty_boost_filesystem
    PRIVATE
      thirdparty_cxx_settings

    PUBLIC
      thirdparty_boost_assert
      thirdparty_boost_config
      thirdparty_boost_container_hash
      thirdparty_boost_core
      thirdparty_boost_detail
      thirdparty_boost_io
      thirdparty_boost_iterator
      thirdparty_boost_smart_ptr
      thirdparty_boost_system
      thirdparty_boost_type_traits
      thirdparty_boost_predef
      thirdparty_boost_atomic
  )

  target_compile_definitions(thirdparty_boost_filesystem PUBLIC
    BOOST_FILESYSTEM_STATIC_LINK
    BOOST_FILESYSTEM_NO_CXX20_ATOMIC_REF
  )

  if(PLATFORM_WINDOWS)
    target_sources(thirdparty_boost_filesystem PRIVATE
      "${library_root}/src/windows_file_codecvt.cpp"
    )

    target_link_libraries(thirdparty_boost_filesystem PUBLIC
      thirdparty_boost_winapi
    )
  endif()
endfunction()

function(generateBoostContext)
  set(library_root "${BOOST_ROOT}/libs/context")

  set(context_backend "fcontext")
  if(OSQUERY_ENABLE_ADDRESS_SANITIZER AND NOT PLATFORM_WINDOWS)
    set(context_backend "ucontext")
  endif()

  message(STATUS "osquery: boost::context is using the ${context_backend} backend")

  if(context_backend STREQUAL "fcontext")
    if(PLATFORM_LINUX)
      if(TARGET_PROCESSOR STREQUAL "x86_64")
        set(source_file_list
          "${library_root}/src/asm/jump_x86_64_sysv_elf_gas.S"
          "${library_root}/src/asm/make_x86_64_sysv_elf_gas.S"
          "${library_root}/src/asm/ontop_x86_64_sysv_elf_gas.S"
        )

      elseif(TARGET_PROCESSOR STREQUAL "aarch64")
        set(source_file_list
          "${library_root}/src/asm/jump_arm64_aapcs_elf_gas.S"
          "${library_root}/src/asm/make_arm64_aapcs_elf_gas.S"
          "${library_root}/src/asm/ontop_arm64_aapcs_elf_gas.S"
        )
      endif()

    elseif(PLATFORM_MACOS)
      if(TARGET_PROCESSOR STREQUAL "x86_64")
        set(source_file_list
          "${library_root}/src/asm/jump_x86_64_sysv_macho_gas.S"
          "${library_root}/src/asm/make_x86_64_sysv_macho_gas.S"
          "${library_root}/src/asm/ontop_x86_64_sysv_macho_gas.S"
        )

      elseif(TARGET_PROCESSOR STREQUAL "aarch64")
        set(source_file_list
        "${library_root}/src/asm/jump_arm64_aapcs_macho_gas.S"
        "${library_root}/src/asm/make_arm64_aapcs_macho_gas.S"
        "${library_root}/src/asm/ontop_arm64_aapcs_macho_gas.S"
      )
      endif()

    elseif(PLATFORM_WINDOWS AND TARGET_PROCESSOR STREQUAL "x86_64")
      if(CMAKE_SIZEOF_VOID_P EQUAL 4)
        set(source_file_list
          "${library_root}/src/asm/jump_i386_ms_pe_masm.asm"
          "${library_root}/src/asm/make_i386_ms_pe_masm.asm"
          "${library_root}/src/asm/ontop_i386_ms_pe_masm.asm"
        )

      else()
        set(source_file_list
          "${library_root}/src/asm/jump_x86_64_ms_pe_masm.asm"
          "${library_root}/src/asm/make_x86_64_ms_pe_masm.asm"
          "${library_root}/src/asm/ontop_x86_64_ms_pe_masm.asm"
        )
      endif()
    endif()

    if(source_file_list STREQUAL "")
      message(FATAL_ERROR "Unsupported platform and/or architecture")
    endif()

    foreach(asm_source_file ${source_file_list})
      if(DEFINED PLATFORM_POSIX)
        set_property(SOURCE "${asm_source_file}" PROPERTY LANGUAGE ASM)
      endif()

      if(DEFINED PLATFORM_MACOS)
        set_property(SOURCE "${asm_source_file}" PROPERTY COMPILE_FLAGS "-x assembler-with-cpp")
      endif()

      if(DEFINED PLATFORM_WINDOWS)
        set_property(SOURCE "${asm_source_file}" PROPERTY COMPILE_FLAGS "/Cp /Cx /Zp4 /safeseh")
      endif()
    endforeach()

  elseif(context_backend STREQUAL "ucontext" OR
         context_backend STREQUAL "winfib")

    set(source_file_list
      "${library_root}/src/continuation.cpp"
      "${library_root}/src/fiber.cpp"
    )
  else()
    message(FATAL_ERROR "Unsupported boost_context backend")
  endif()

  if(PLATFORM_POSIX)
    list(APPEND source_file_list
      "${library_root}/src/posix/stack_traits.cpp"
    )

  elseif(PLATFORM_WINDOWS)
    list(APPEND source_file_list
      "${library_root}/src/windows/stack_traits.cpp"
    )
  endif()

  if(source_file_list STREQUAL "")
    message(FATAL_ERROR "Unsupported platform and/or architecture")
  endif()

  add_library(thirdparty_boost_context STATIC EXCLUDE_FROM_ALL
    ${source_file_list}
  )

  if(context_backend STREQUAL "ucontext")
    target_compile_definitions(thirdparty_boost_context PUBLIC
      BOOST_USE_UCONTEXT
    )

    if(OSQUERY_ENABLE_ADDRESS_SANITIZER)
      target_compile_definitions(thirdparty_boost_context PUBLIC
        BOOST_USE_ASAN
      )
    endif()

  elseif(context_backend STREQUAL "winfib")
    target_compile_definitions(thirdparty_boost_context PUBLIC
      BOOST_USE_WINFIB
    )
  endif()

  target_include_directories(thirdparty_boost_context SYSTEM PUBLIC
    "${library_root}/include"
  )

  target_link_libraries(thirdparty_boost_context
    PRIVATE
      thirdparty_cxx_settings

    PUBLIC
      thirdparty_boost_assert
      thirdparty_boost_config
      thirdparty_boost_core
      thirdparty_boost_mp11
      thirdparty_boost_pool
      thirdparty_boost_predef
      thirdparty_boost_smart_ptr
  )

  target_compile_definitions(thirdparty_boost_context
    PRIVATE
      BOOST_CONTEXT_SOURCE

    PUBLIC
      BOOST_CONTEXT_NO_LIB
      BOOST_CONTEXT_STATIC_LINK
      BOOST_CONTEXT_EXPORT
  )
endfunction()

boostMain()

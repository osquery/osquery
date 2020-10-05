# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(boostMain)
  set(BOOST_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/src")

  importBoostInterfaceLibraries()

  generateBoostLocale()
  generateBoostContext()
  generateBoostCoroutine()
  generateBoostFilesystem()
  generateBoostRegex()
  generateBoostThread()
  generateBoostAtomic()
  generateBoostDateTime()
  generateBoostNumericConversion()
  generateBoostContainer()
  generateBoostMath()
  generateBoostChrono()
  generateBoostException()
  generateBoostSerialization()
  generateBoostRandom()
  generateBoostIostreams()
  generateBoostWinapi()
  generateBoostEndian()

  add_library(thirdparty_boost INTERFACE)

  target_link_libraries(thirdparty_boost INTERFACE
    thirdparty_boost_coroutine
    thirdparty_boost_filesystem
    thirdparty_boost_regex
    thirdparty_boost_locale
    thirdparty_boost_format
    thirdparty_boost_variant
    thirdparty_boost_serialization
    thirdparty_boost_coroutine2
    thirdparty_boost_propertytree
    thirdparty_boost_asio
    thirdparty_boost_uuid
    thirdparty_boost_beast
    thirdparty_boost_xpressive
    thirdparty_boost_process
    thirdparty_boost_iostreams
    thirdparty_boost_winapi
    thirdparty_boost_circularbuffer
    thirdparty_boost_endian
  )
endfunction()

function(generateBoostSerialization)
  set(library_root "${BOOST_ROOT}/libs/serialization")

  add_library(thirdparty_boost_serialization STATIC
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
    "${library_root}/src/basic_text_wiprimitive.cpp"
    "${library_root}/src/basic_text_woprimitive.cpp"
    "${library_root}/src/basic_xml_archive.cpp"
    "${library_root}/src/basic_xml_grammar.ipp"
    "${library_root}/src/binary_iarchive.cpp"
    "${library_root}/src/binary_oarchive.cpp"
    "${library_root}/src/binary_wiarchive.cpp"
    "${library_root}/src/binary_woarchive.cpp"
    "${library_root}/src/codecvt_null.cpp"
    "${library_root}/src/extended_type_info.cpp"
    "${library_root}/src/extended_type_info_no_rtti.cpp"
    "${library_root}/src/extended_type_info_typeid.cpp"
    "${library_root}/src/polymorphic_binary_iarchive.cpp"
    "${library_root}/src/polymorphic_binary_oarchive.cpp"
    "${library_root}/src/polymorphic_iarchive.cpp"
    "${library_root}/src/polymorphic_oarchive.cpp"
    "${library_root}/src/polymorphic_text_iarchive.cpp"
    "${library_root}/src/polymorphic_text_oarchive.cpp"
    "${library_root}/src/polymorphic_text_wiarchive.cpp"
    "${library_root}/src/polymorphic_text_woarchive.cpp"
    "${library_root}/src/polymorphic_xml_iarchive.cpp"
    "${library_root}/src/polymorphic_xml_oarchive.cpp"
    "${library_root}/src/polymorphic_xml_wiarchive.cpp"
    "${library_root}/src/polymorphic_xml_woarchive.cpp"
    "${library_root}/src/stl_port.cpp"
    "${library_root}/src/text_iarchive.cpp"
    "${library_root}/src/text_oarchive.cpp"
    "${library_root}/src/text_wiarchive.cpp"
    "${library_root}/src/text_woarchive.cpp"
    "${library_root}/src/utf8_codecvt_facet.cpp"
    "${library_root}/src/void_cast.cpp"
    "${library_root}/src/xml_archive_exception.cpp"
    "${library_root}/src/xml_grammar.cpp"
    "${library_root}/src/xml_iarchive.cpp"
    "${library_root}/src/xml_oarchive.cpp"
    "${library_root}/src/xml_wgrammar.cpp"
    "${library_root}/src/xml_wiarchive.cpp"
    "${library_root}/src/xml_woarchive.cpp"
  )

  target_include_directories(thirdparty_boost_serialization SYSTEM PUBLIC
    "${library_root}/include"
  )

  target_link_libraries(thirdparty_boost_serialization PUBLIC
    thirdparty_boost_assert
    thirdparty_boost_core
    thirdparty_boost_integer
    thirdparty_boost_mpl
    thirdparty_boost_utility
    thirdparty_boost_typetraits
    thirdparty_boost_io
    thirdparty_boost_smartptr
    thirdparty_boost_iterator
    thirdparty_boost_spirit
    thirdparty_boost_array
    thirdparty_boost_function
  )

  target_link_libraries(thirdparty_boost_serialization PRIVATE
    thirdparty_cxx_settings
  )
endfunction()

function(generateBoostNumericConversion)
  set(library_root "${BOOST_ROOT}/libs/numeric/conversion")

  add_library(thirdparty_boost_numericconversion INTERFACE)

  target_include_directories(thirdparty_boost_numericconversion SYSTEM INTERFACE
    "${library_root}/include"
  )

  target_link_libraries(thirdparty_boost_numericconversion INTERFACE
    thirdparty_boost_config
  )
endfunction()

function(generateBoostEndian)
  set(library_root "${BOOST_ROOT}/libs/endian")

  add_library(thirdparty_boost_endian INTERFACE)

  target_include_directories(thirdparty_boost_endian SYSTEM INTERFACE
    "${library_root}/include"
    )

  target_link_libraries(thirdparty_boost_endian INTERFACE
    thirdparty_boost_config
    )
endfunction()

function(generateBoostRandom)
  set(library_root "${BOOST_ROOT}/libs/random")

  add_library(thirdparty_boost_random STATIC
    "${library_root}/src/random_device.cpp"
  )

  target_include_directories(thirdparty_boost_random SYSTEM PUBLIC
    "${library_root}/include"
  )

  target_link_libraries(thirdparty_boost_random PUBLIC
    thirdparty_boost_core
    thirdparty_boost_system
    thirdparty_boost_throwexception
    thirdparty_boost_winapi
  )

  target_link_libraries(thirdparty_boost_random PRIVATE
    thirdparty_cxx_settings
  )
endfunction()

function(importBoostInterfaceLibrary folder_name)
  if(folder_name STREQUAL "process")
    set(library_root "${OSQUERY_boost_src_libs_process_ROOT_DIR}")
  else()
    set(library_root "${BOOST_ROOT}/libs/${folder_name}")
  endif()

  string(REPLACE "_" "" target_name "${folder_name}")
  set(target_name "thirdparty_boost_${target_name}")

  add_library("${target_name}" INTERFACE)

  target_include_directories("${target_name}" SYSTEM INTERFACE
    "${library_root}/include"
  )

  if("${folder_name}" STREQUAL "uuid")
    target_compile_definitions(${target_name} INTERFACE
      BOOST_UUID_RANDOM_PROVIDER_FORCE_POSIX)
  endif()

  if(DEFINED PLATFORM_WINDOWS)
    if("${folder_name}" STREQUAL "asio")
      target_compile_definitions(${target_name} INTERFACE
        BOOST_ASIO_WINDOWS
      )
    endif()
  endif()

  foreach(additional_dependency ${ARGN})

    if(additional_dependency MATCHES "^thirdparty_")
      target_link_libraries("${target_name}" INTERFACE
        "${additional_dependency}"
      )
    else()
      string(REPLACE "_" "" additional_dependency "${additional_dependency}")

      target_link_libraries("${target_name}" INTERFACE
        "thirdparty_boost_${additional_dependency}"
      )
    endif()
  endforeach()
endfunction()

function(importBoostInterfaceLibraries)
  set(library_descriptor_list
    "fusion:config"
    "logic:config"
    "conversion:config"
    "xpressive:proto,fusion,conversion"
    "proto:config"
    "beast:mp11,logic"
    "mp11:config"
    "unordered:config"
    "function_types:config"
    "tti:function_types"
    "uuid:random,tti"
    "asio:config,thirdparty_openssl"
    "any:config"
    "foreach:config"
    "multi_index:foreach"
    "property_tree:any,multi_index"
    "spirit:optional"
    "algorithm:config"
    "variant:config"
    "format:config"
    "optional:config"
    "type_index:container_hash"
    "coroutine2:container_hash"
    "function:type_index,bind"
    "ratio:type_traits,core,integer"
    "multiprecision:config"
    "tokenizer:config"
    "intrusive:config"
    "array:config"
    "range:iterator,concept_check"
    "concept_check:config"
    "utility:core"
    "throw_exception:assert"
    "move:assert,static_assert"
    "container_hash:detail"
    "io:config"
    "detail:config"
    "mpl:preprocessor"
    "static_assert:config"
    "core:config"
    "type_traits:static_assert,assert"
    "preprocessor:config"
    "bind:config"
    "smart_ptr:predef,throw_exception,move"
    "assert:config"
    "iterator:mpl,assert,detail"
    "predef:config"
    "integer:config"
    "lexical_cast:range,numeric_conversion,integer,array,container,math"
    "system:config"
    "tuple:config"
    "process:config"
    "circular_buffer:config"
    "scope_exit:typeof,config"
    "typeof:config"
  )

  add_library(thirdparty_boost_config INTERFACE)
  target_include_directories(thirdparty_boost_config SYSTEM INTERFACE
    "${BOOST_ROOT}/libs/config/include"
  )

  foreach(library_descriptor ${library_descriptor_list})
    string(REPLACE ":" ";" temp "${library_descriptor}")
    list(GET temp 0 library_name)
    list(GET temp 1 library_dependency_list)

    string(REPLACE "," ";" library_dependency_list "${library_dependency_list}")

    importBoostInterfaceLibrary("${library_name}" ${library_dependency_list})
  endforeach()
endfunction()

function(generateBoostWinapi)
  add_library(thirdparty_boost_winapi INTERFACE)

  set(library_root "${BOOST_ROOT}/libs/winapi")

  target_include_directories(thirdparty_boost_winapi SYSTEM INTERFACE
    "${library_root}/include"
  )

  if(DEFINED PLATFORM_WINDOWS)
    target_compile_definitions(thirdparty_boost_winapi INTERFACE
      BOOST_USE_WINDOWS_H
      NOMINMAX
    )
  endif()

  target_link_libraries(thirdparty_boost_winapi INTERFACE
    thirdparty_boost_config
    thirdparty_boost_predef
  )
endfunction()

function(generateBoostLocale)
  set(library_root "${BOOST_ROOT}/libs/locale")

  add_library(thirdparty_boost_locale STATIC
    #"${library_root}/src/encoding/codepage.cpp"
    "${library_root}/src/icu/boundary.cpp"
    "${library_root}/src/icu/codecvt.cpp"
    "${library_root}/src/icu/collator.cpp"
    "${library_root}/src/icu/conversion.cpp"
    "${library_root}/src/icu/date_time.cpp"
    "${library_root}/src/icu/formatter.cpp"
    "${library_root}/src/icu/icu_backend.cpp"
    "${library_root}/src/icu/numeric.cpp"
    "${library_root}/src/icu/time_zone.cpp"
    "${library_root}/src/shared/date_time.cpp"
    "${library_root}/src/shared/format.cpp"
    "${library_root}/src/shared/formatting.cpp"
    "${library_root}/src/shared/generator.cpp"
    "${library_root}/src/shared/ids.cpp"
    "${library_root}/src/shared/localization_backend.cpp"
    "${library_root}/src/shared/message.cpp"
    "${library_root}/src/shared/mo_lambda.cpp"
    "${library_root}/src/std/codecvt.cpp"
    "${library_root}/src/std/collate.cpp"
    "${library_root}/src/std/converter.cpp"
    "${library_root}/src/std/numeric.cpp"
    "${library_root}/src/std/std_backend.cpp"
    "${library_root}/src/util/codecvt_converter.cpp"
    "${library_root}/src/util/default_locale.cpp"
    "${library_root}/src/util/gregorian.cpp"
    "${library_root}/src/util/info.cpp"
    "${library_root}/src/util/locale_data.cpp"
  )

  if(DEFINED PLATFORM_POSIX)
    target_sources(thirdparty_boost_locale PRIVATE
      "${library_root}/src/posix/codecvt.cpp"
      "${library_root}/src/posix/collate.cpp"
      "${library_root}/src/posix/converter.cpp"
      "${library_root}/src/posix/numeric.cpp"
      "${library_root}/src/posix/posix_backend.cpp"
    )

  elseif(DEFINED PLATFORM_WINDOWS)
    target_sources(thirdparty_boost_locale PRIVATE
      "${library_root}/src/win32/collate.cpp"
      "${library_root}/src/win32/converter.cpp"
      "${library_root}/src/win32/lcid.cpp"
      "${library_root}/src/win32/numeric.cpp"
      "${library_root}/src/win32/win_backend.cpp"
    )
  endif()

  target_include_directories(thirdparty_boost_locale SYSTEM PUBLIC
    "${library_root}/include"
  )

  target_include_directories(thirdparty_boost_locale PRIVATE
    "${library_root}/src"
    "${library_root}/src/encoding"
    "${library_root}/src/icu"
    "${library_root}/src/shared"
    "${library_root}/src/std"
    "${library_root}/src/util"
  )

  target_link_libraries(thirdparty_boost_locale PUBLIC
    thirdparty_boost_assert
    thirdparty_boost_iterator
    thirdparty_boost_typetraits
    thirdparty_boost_core
    thirdparty_boost_thread
    thirdparty_boost_unordered
    thirdparty_icu
  )

  target_link_libraries(thirdparty_boost_locale PRIVATE
    thirdparty_cxx_settings
  )
endfunction()

function(generateBoostException)
  set(library_root "${BOOST_ROOT}/libs/exception")

  add_library(thirdparty_boost_exception STATIC
    "${library_root}/src/clone_current_exception_non_intrusive.cpp"
  )

  target_include_directories(thirdparty_boost_exception SYSTEM PUBLIC
    "${library_root}/include"
  )

  target_link_libraries(thirdparty_boost_exception PUBLIC
    thirdparty_boost_config
  )

  target_link_libraries(thirdparty_boost_exception PRIVATE
    thirdparty_cxx_settings
  )
endfunction()

function(generateBoostChrono)
  set(library_root "${BOOST_ROOT}/libs/chrono")

  add_library(thirdparty_boost_chrono STATIC
    "${library_root}/src/chrono.cpp"
    "${library_root}/src/process_cpu_clocks.cpp"
    "${library_root}/src/thread_clock.cpp"
  )

  target_include_directories(thirdparty_boost_chrono SYSTEM PUBLIC
    "${library_root}/include"
  )

  target_link_libraries(thirdparty_boost_chrono PUBLIC
    thirdparty_boost_predef
    thirdparty_boost_mpl
    thirdparty_boost_ratio
    thirdparty_boost_system
    thirdparty_boost_throwexception
    thirdparty_boost_utility
    thirdparty_boost_winapi
  )

  target_link_libraries(thirdparty_boost_chrono PRIVATE
    thirdparty_cxx_settings
  )
endfunction()

function(generateBoostMath)
  set(library_root "${BOOST_ROOT}/libs/math")

  add_library(thirdparty_boost_math STATIC
    "${library_root}/src/tr1"
    "${library_root}/src/tr1/acosh.cpp"
    "${library_root}/src/tr1/acoshf.cpp"
    "${library_root}/src/tr1/acoshl.cpp"
    "${library_root}/src/tr1/asinh.cpp"
    "${library_root}/src/tr1/asinhf.cpp"
    "${library_root}/src/tr1/asinhl.cpp"
    "${library_root}/src/tr1/assoc_laguerre.cpp"
    "${library_root}/src/tr1/assoc_laguerref.cpp"
    "${library_root}/src/tr1/assoc_laguerrel.cpp"
    "${library_root}/src/tr1/assoc_legendre.cpp"
    "${library_root}/src/tr1/assoc_legendref.cpp"
    "${library_root}/src/tr1/assoc_legendrel.cpp"
    "${library_root}/src/tr1/atanh.cpp"
    "${library_root}/src/tr1/atanhf.cpp"
    "${library_root}/src/tr1/atanhl.cpp"
    "${library_root}/src/tr1/beta.cpp"
    "${library_root}/src/tr1/betaf.cpp"
    "${library_root}/src/tr1/betal.cpp"
    "${library_root}/src/tr1/c_policy.hpp"
    "${library_root}/src/tr1/cbrt.cpp"
    "${library_root}/src/tr1/cbrtf.cpp"
    "${library_root}/src/tr1/cbrtl.cpp"
    "${library_root}/src/tr1/comp_ellint_1.cpp"
    "${library_root}/src/tr1/comp_ellint_1f.cpp"
    "${library_root}/src/tr1/comp_ellint_1l.cpp"
    "${library_root}/src/tr1/comp_ellint_2.cpp"
    "${library_root}/src/tr1/comp_ellint_2f.cpp"
    "${library_root}/src/tr1/comp_ellint_2l.cpp"
    "${library_root}/src/tr1/comp_ellint_3.cpp"
    "${library_root}/src/tr1/comp_ellint_3f.cpp"
    "${library_root}/src/tr1/comp_ellint_3l.cpp"
    "${library_root}/src/tr1/copysign.cpp"
    "${library_root}/src/tr1/copysignf.cpp"
    "${library_root}/src/tr1/copysignl.cpp"
    "${library_root}/src/tr1/cyl_bessel_i.cpp"
    "${library_root}/src/tr1/cyl_bessel_if.cpp"
    "${library_root}/src/tr1/cyl_bessel_il.cpp"
    "${library_root}/src/tr1/cyl_bessel_j.cpp"
    "${library_root}/src/tr1/cyl_bessel_jf.cpp"
    "${library_root}/src/tr1/cyl_bessel_jl.cpp"
    "${library_root}/src/tr1/cyl_bessel_k.cpp"
    "${library_root}/src/tr1/cyl_bessel_kf.cpp"
    "${library_root}/src/tr1/cyl_bessel_kl.cpp"
    "${library_root}/src/tr1/cyl_neumann.cpp"
    "${library_root}/src/tr1/cyl_neumannf.cpp"
    "${library_root}/src/tr1/cyl_neumannl.cpp"
    "${library_root}/src/tr1/ellint_1.cpp"
    "${library_root}/src/tr1/ellint_1f.cpp"
    "${library_root}/src/tr1/ellint_1l.cpp"
    "${library_root}/src/tr1/ellint_2.cpp"
    "${library_root}/src/tr1/ellint_2f.cpp"
    "${library_root}/src/tr1/ellint_2l.cpp"
    "${library_root}/src/tr1/ellint_3.cpp"
    "${library_root}/src/tr1/ellint_3f.cpp"
    "${library_root}/src/tr1/ellint_3l.cpp"
    "${library_root}/src/tr1/erf.cpp"
    "${library_root}/src/tr1/erfc.cpp"
    "${library_root}/src/tr1/erfcf.cpp"
    "${library_root}/src/tr1/erfcl.cpp"
    "${library_root}/src/tr1/erff.cpp"
    "${library_root}/src/tr1/erfl.cpp"
    "${library_root}/src/tr1/expint.cpp"
    "${library_root}/src/tr1/expintf.cpp"
    "${library_root}/src/tr1/expintl.cpp"
    "${library_root}/src/tr1/expm1.cpp"
    "${library_root}/src/tr1/expm1f.cpp"
    "${library_root}/src/tr1/expm1l.cpp"
    "${library_root}/src/tr1/fmax.cpp"
    "${library_root}/src/tr1/fmaxf.cpp"
    "${library_root}/src/tr1/fmaxl.cpp"
    "${library_root}/src/tr1/fmin.cpp"
    "${library_root}/src/tr1/fminf.cpp"
    "${library_root}/src/tr1/fminl.cpp"
    "${library_root}/src/tr1/fpclassify.cpp"
    "${library_root}/src/tr1/fpclassifyf.cpp"
    "${library_root}/src/tr1/fpclassifyl.cpp"
    "${library_root}/src/tr1/hermite.cpp"
    "${library_root}/src/tr1/hermitef.cpp"
    "${library_root}/src/tr1/hermitel.cpp"
    "${library_root}/src/tr1/hypot.cpp"
    "${library_root}/src/tr1/hypotf.cpp"
    "${library_root}/src/tr1/hypotl.cpp"
    "${library_root}/src/tr1/laguerre.cpp"
    "${library_root}/src/tr1/laguerref.cpp"
    "${library_root}/src/tr1/laguerrel.cpp"
    "${library_root}/src/tr1/legendre.cpp"
    "${library_root}/src/tr1/legendref.cpp"
    "${library_root}/src/tr1/legendrel.cpp"
    "${library_root}/src/tr1/lgamma.cpp"
    "${library_root}/src/tr1/lgammaf.cpp"
    "${library_root}/src/tr1/lgammal.cpp"
    "${library_root}/src/tr1/llround.cpp"
    "${library_root}/src/tr1/llroundf.cpp"
    "${library_root}/src/tr1/llroundl.cpp"
    "${library_root}/src/tr1/log1p.cpp"
    "${library_root}/src/tr1/log1pf.cpp"
    "${library_root}/src/tr1/log1pl.cpp"
    "${library_root}/src/tr1/lround.cpp"
    "${library_root}/src/tr1/lroundf.cpp"
    "${library_root}/src/tr1/lroundl.cpp"
    "${library_root}/src/tr1/nextafter.cpp"
    "${library_root}/src/tr1/nextafterf.cpp"
    "${library_root}/src/tr1/nextafterl.cpp"
    "${library_root}/src/tr1/nexttoward.cpp"
    "${library_root}/src/tr1/nexttowardf.cpp"
    "${library_root}/src/tr1/nexttowardl.cpp"
    "${library_root}/src/tr1/pch.hpp"
    "${library_root}/src/tr1/riemann_zeta.cpp"
    "${library_root}/src/tr1/riemann_zetaf.cpp"
    "${library_root}/src/tr1/riemann_zetal.cpp"
    "${library_root}/src/tr1/round.cpp"
    "${library_root}/src/tr1/roundf.cpp"
    "${library_root}/src/tr1/roundl.cpp"
    "${library_root}/src/tr1/sph_bessel.cpp"
    "${library_root}/src/tr1/sph_besself.cpp"
    "${library_root}/src/tr1/sph_bessell.cpp"
    "${library_root}/src/tr1/sph_legendre.cpp"
    "${library_root}/src/tr1/sph_legendref.cpp"
    "${library_root}/src/tr1/sph_legendrel.cpp"
    "${library_root}/src/tr1/sph_neumann.cpp"
    "${library_root}/src/tr1/sph_neumannf.cpp"
    "${library_root}/src/tr1/sph_neumannl.cpp"
    "${library_root}/src/tr1/tgamma.cpp"
    "${library_root}/src/tr1/tgammaf.cpp"
    "${library_root}/src/tr1/tgammal.cpp"
    "${library_root}/src/tr1/trunc.cpp"
    "${library_root}/src/tr1/truncf.cpp"
    "${library_root}/src/tr1/truncl.cpp"
  )

  target_include_directories(thirdparty_boost_math SYSTEM PUBLIC
    "${library_root}/include"
  )

  target_include_directories(thirdparty_boost_math PRIVATE
    "${library_root}/src/tr1"
  )

  target_link_libraries(thirdparty_boost_math PUBLIC
    thirdparty_boost_staticassert
    thirdparty_boost_predef
    thirdparty_boost_typetraits
    thirdparty_boost_mpl
    thirdparty_boost_throwexception
    thirdparty_boost_utility
    thirdparty_boost_array
    thirdparty_boost_lexicalcast
    thirdparty_boost_smartptr
    thirdparty_boost_multiprecision
    thirdparty_boost_io
    thirdparty_boost_tokenizer
  )

  target_link_libraries(thirdparty_boost_math PRIVATE
    thirdparty_cxx_settings
  )
endfunction()

function(generateBoostContainer)
  set(library_root "${BOOST_ROOT}/libs/container")

  add_library(thirdparty_boost_container STATIC
    "${library_root}/src/dlmalloc.cpp"
    "${library_root}/src/global_resource.cpp"
    "${library_root}/src/monotonic_buffer_resource.cpp"
    "${library_root}/src/pool_resource.cpp"
    "${library_root}/src/synchronized_pool_resource.cpp"
    "${library_root}/src/unsynchronized_pool_resource.cpp"
  )

  target_include_directories(thirdparty_boost_container SYSTEM PUBLIC
    "${library_root}/include"
  )

  target_link_libraries(thirdparty_boost_container PUBLIC
    thirdparty_boost_move
    thirdparty_boost_core
    thirdparty_boost_intrusive
  )

  target_link_libraries(thirdparty_boost_container PRIVATE
    thirdparty_cxx_settings
  )
endfunction()

function(generateBoostDateTime)
  set(library_root "${BOOST_ROOT}/libs/date_time")

  add_library(thirdparty_boost_datetime STATIC
    "${library_root}/src/gregorian/date_generators.cpp"
    "${library_root}/src/gregorian/greg_month.cpp"
    "${library_root}/src/gregorian/greg_names.hpp"
    "${library_root}/src/gregorian/greg_weekday.cpp"
    "${library_root}/src/gregorian/gregorian_types.cpp"
    "${library_root}/src/posix_time/posix_time_types.cpp"
  )

  target_include_directories(thirdparty_boost_datetime SYSTEM PUBLIC
    "${library_root}/include"
  )

  target_link_libraries(thirdparty_boost_datetime PUBLIC
    thirdparty_boost_throwexception
    thirdparty_boost_utility
    thirdparty_boost_mpl
    thirdparty_boost_typetraits
    thirdparty_boost_smartptr
    thirdparty_boost_lexicalcast
  )

  target_link_libraries(thirdparty_boost_datetime PRIVATE
    thirdparty_cxx_settings
  )
endfunction()

function(generateBoostContext)
  set(library_root "${BOOST_ROOT}/libs/context")

  set(source_files
    "${library_root}/src/execution_context.cpp"
  )

  if(DEFINED PLATFORM_LINUX AND TARGET_PROCESSOR STREQUAL "x86_64")
    set(asm_source_file_list
      "${library_root}/src/asm/jump_x86_64_sysv_elf_gas.S"
      "${library_root}/src/asm/make_x86_64_sysv_elf_gas.S"
      "${library_root}/src/asm/ontop_x86_64_sysv_elf_gas.S"
    )
  elseif(DEFINED PLATFORM_LINUX AND TARGET_PROCESSOR STREQUAL "aarch64")
    set(asm_source_file_list
      "${library_root}/src/asm/jump_arm64_aapcs_elf_gas.S"
      "${library_root}/src/asm/make_arm64_aapcs_elf_gas.S"
      "${library_root}/src/asm/ontop_arm64_aapcs_elf_gas.S"
    )
  elseif(DEFINED PLATFORM_MACOS)
    set(asm_source_file_list
      "${library_root}/src/asm/jump_x86_64_sysv_macho_gas.S"
      "${library_root}/src/asm/make_x86_64_sysv_macho_gas.S"
      "${library_root}/src/asm/ontop_x86_64_sysv_macho_gas.S"
    )
  elseif(DEFINED PLATFORM_WINDOWS)
    if(CMAKE_SIZEOF_VOID_P EQUAL 4)
      set(asm_source_file_list
        "${library_root}/src/asm/jump_i386_ms_pe_masm.asm"
        "${library_root}/src/asm/make_i386_ms_pe_masm.asm"
        "${library_root}/src/asm/ontop_i386_ms_pe_masm.asm"
      )
    else()
      set(asm_source_file_list
        "${library_root}/src/asm/jump_x86_64_ms_pe_masm.asm"
        "${library_root}/src/asm/make_x86_64_ms_pe_masm.asm"
        "${library_root}/src/asm/ontop_x86_64_ms_pe_masm.asm"
      )
    endif()
  endif()

  foreach(asm_source_file ${asm_source_file_list})
    if(DEFINED PLATFORM_POSIX)
      set_property(SOURCE "${asm_source_file}" PROPERTY LANGUAGE C)
    endif()

    if(DEFINED PLATFORM_MACOS)
      set_property(SOURCE "${asm_source_file}" PROPERTY COMPILE_FLAGS "-x assembler-with-cpp")
    endif()

    if(DEFINED PLATFORM_WINDOWS)
      set_property(SOURCE "${asm_source_file}" PROPERTY COMPILE_FLAGS "/Cp /Cx /Zp4 /safeseh")
    endif()
  endforeach()

  if(OSQUERY_ENABLE_ADDRESS_SANITIZER)
    list(APPEND source_files
      "${library_root}/src/fiber.cpp"
    )
  endif()

  add_library(thirdparty_boost_context STATIC
    ${source_files}
    ${asm_source_file_list}
  )

  if(DEFINED PLATFORM_POSIX)
    target_sources(thirdparty_boost_context PRIVATE
      "${library_root}/src/posix/stack_traits.cpp"
    )

  elseif(DEFINED PLATFORM_WINDOWS)
    target_sources(thirdparty_boost_context PRIVATE
      "${library_root}/src/windows/stack_traits.cpp"
    )

    target_compile_definitions(thirdparty_boost_context PRIVATE
      BOOST_CONTEXT_EXPORT=
    )

  endif()

  target_include_directories(thirdparty_boost_context SYSTEM PUBLIC
    "${library_root}/include"
  )

  target_link_libraries(thirdparty_boost_context PUBLIC
    thirdparty_boost_config
    thirdparty_boost_assert
    thirdparty_boost_smartptr
  )

  target_link_libraries(thirdparty_boost_context PRIVATE
    thirdparty_cxx_settings
  )
endfunction()

function(generateBoostCoroutine)
  set(library_root "${BOOST_ROOT}/libs/coroutine")

  add_library(thirdparty_boost_coroutine STATIC
    "${library_root}/src/exceptions.cpp"
    "${library_root}/src/detail/coroutine_context.cpp"
  )

  if(DEFINED PLATFORM_POSIX)
    target_sources(thirdparty_boost_coroutine PRIVATE
      "${library_root}/src/posix/stack_traits.cpp"
    )

  elseif(DEFINED PLATFORM_WINDOWS)
    target_sources(thirdparty_boost_coroutine PRIVATE
      "${library_root}/src/windows/stack_traits.cpp"
    )
  endif()

  target_include_directories(thirdparty_boost_coroutine SYSTEM PUBLIC
    "${library_root}/include"
  )

  target_link_libraries(thirdparty_boost_coroutine PUBLIC
    thirdparty_boost_core
    thirdparty_boost_system
    thirdparty_boost_typetraits
    thirdparty_boost_context
    thirdparty_boost_thread
  )

  target_link_libraries(thirdparty_boost_coroutine PRIVATE
    thirdparty_cxx_settings
  )
endfunction()

function(generateBoostFilesystem)
  set(library_root "${BOOST_ROOT}/libs/filesystem")

  add_library(thirdparty_boost_filesystem STATIC
    "${library_root}/src/codecvt_error_category.cpp"
    "${library_root}/src/operations.cpp"
    "${library_root}/src/path.cpp"
    "${library_root}/src/path_traits.cpp"
    "${library_root}/src/portability.cpp"
    "${library_root}/src/unique_path.cpp"
    "${library_root}/src/utf8_codecvt_facet.cpp"
  )

  if(DEFINED PLATFORM_WINDOWS)
    target_sources(thirdparty_boost_filesystem PRIVATE
      "${library_root}/src/windows_file_codecvt.cpp"
    )
  endif()

  target_include_directories(thirdparty_boost_filesystem SYSTEM PUBLIC
    "${library_root}/include"
  )

  target_link_libraries(thirdparty_boost_filesystem PUBLIC
    thirdparty_boost_system
    thirdparty_boost_typetraits
    thirdparty_boost_core
    thirdparty_boost_iterator
    thirdparty_boost_io
    thirdparty_boost_containerhash
    thirdparty_boost_smartptr
    thirdparty_boost_winapi
  )

  target_link_libraries(thirdparty_boost_filesystem PRIVATE
    thirdparty_cxx_settings
  )
endfunction()

function(generateBoostRegex)
  set(library_root "${BOOST_ROOT}/libs/regex")

  add_library(thirdparty_boost_regex STATIC
    "${library_root}/src/cpp_regex_traits.cpp"
    "${library_root}/src/cregex.cpp"
    "${library_root}/src/c_regex_traits.cpp"
    "${library_root}/src/fileiter.cpp"
    "${library_root}/src/icu.cpp"
    "${library_root}/src/instances.cpp"
    "${library_root}/src/internals.hpp"
    "${library_root}/src/posix_api.cpp"
    "${library_root}/src/regex.cpp"
    "${library_root}/src/regex_debug.cpp"
    "${library_root}/src/regex_raw_buffer.cpp"
    "${library_root}/src/regex_traits_defaults.cpp"
    "${library_root}/src/static_mutex.cpp"
    "${library_root}/src/usinstances.cpp"
    "${library_root}/src/w32_regex_traits.cpp"
    "${library_root}/src/wc_regex_traits.cpp"
    "${library_root}/src/wide_posix_api.cpp"
    "${library_root}/src/winstances.cpp"
  )

  target_include_directories(thirdparty_boost_regex SYSTEM PUBLIC
    "${library_root}/include"
  )

  target_link_libraries(thirdparty_boost_regex PUBLIC
    thirdparty_boost_predef
    thirdparty_boost_assert
    thirdparty_boost_throwexception
    thirdparty_boost_smartptr
    thirdparty_boost_core
    thirdparty_boost_mpl
    thirdparty_boost_typetraits
    thirdparty_boost_integer
    thirdparty_boost_containerhash
  )

  target_link_libraries(thirdparty_boost_regex PRIVATE
    thirdparty_cxx_settings
  )
endfunction()

function(generateBoostAtomic)
  set(library_root "${BOOST_ROOT}/libs/atomic")

  add_library(thirdparty_boost_atomic STATIC
    "${library_root}/src/lockpool.cpp"
  )

  target_include_directories(thirdparty_boost_atomic SYSTEM PUBLIC
    "${library_root}/include"
  )

  target_link_libraries(thirdparty_boost_atomic PUBLIC
    thirdparty_boost_assert
  )

  target_link_libraries(thirdparty_boost_atomic PRIVATE
    thirdparty_cxx_settings
  )
endfunction()

function(generateBoostThread)
  set(library_root "${BOOST_ROOT}/libs/thread")

  add_library(thirdparty_boost_thread STATIC
    "${library_root}/src/future.cpp"
    "${library_root}/src/tss_null.cpp"
  )

  if(DEFINED PLATFORM_POSIX)
    target_sources(thirdparty_boost_thread PRIVATE
      "${library_root}/src/pthread/once.cpp"
      "${library_root}/src/pthread/once_atomic.cpp"
      "${library_root}/src/pthread/thread.cpp"
    )

  elseif(DEFINED PLATFORM_WINDOWS)
    target_sources(thirdparty_boost_thread PRIVATE
      "${library_root}/src/win32/thread.cpp"
      "${library_root}/src/win32/thread_primitives.cpp"
      "${library_root}/src/win32/tss_dll.cpp"
      "${library_root}/src/win32/tss_pe.cpp"
    )

    target_compile_definitions(thirdparty_boost_thread PRIVATE
      BOOST_THREAD_BUILD_LIB
    )
  endif()

  target_include_directories(thirdparty_boost_thread SYSTEM PUBLIC
    "${library_root}/include"
  )

  target_link_libraries(thirdparty_boost_thread PUBLIC
    thirdparty_boost_core
    thirdparty_boost_system
    thirdparty_boost_typetraits
    thirdparty_boost_move
    thirdparty_boost_mpl
    thirdparty_boost_bind
    thirdparty_boost_atomic
    thirdparty_boost_datetime
    thirdparty_boost_chrono
    thirdparty_boost_containerhash
    thirdparty_boost_tuple
    thirdparty_boost_exception
    thirdparty_boost_optional
    thirdparty_boost_function
    thirdparty_boost_typeindex
    thirdparty_boost_algorithm
    thirdparty_boost_winapi
  )

  target_link_libraries(thirdparty_boost_thread PRIVATE
    thirdparty_cxx_settings
  )
endfunction()

function(generateBoostIostreams)
  set(library_root "${BOOST_ROOT}/libs/iostreams")

  add_library(thirdparty_boost_iostreams STATIC
    "${library_root}/src/zlib.cpp"
    "${library_root}/src/gzip.cpp"
    "${library_root}/src/zstd.cpp"
    "${library_root}/src/bzip2.cpp"
  )

  if(DEFINED PLATFORM_POSIX)
    target_sources(thirdparty_boost_iostreams PRIVATE
      "${library_root}/src/lzma.cpp"
    )
  endif()

  target_include_directories(thirdparty_boost_iostreams SYSTEM PUBLIC
    "${library_root}/include"
  )

  target_link_libraries(thirdparty_boost_iostreams PUBLIC
    thirdparty_boost_assert
    thirdparty_boost_throwexception
    thirdparty_boost_smartptr
    thirdparty_boost_core
    thirdparty_boost_mpl
    thirdparty_boost_typetraits
    thirdparty_boost_integer
    thirdparty_boost_containerhash
    thirdparty_boost_range
    thirdparty_boost_utility
    thirdparty_zlib
    thirdparty_zstd
    thirdparty_bzip2
  )

  if(DEFINED PLATFORM_POSIX)
    target_link_libraries(thirdparty_boost_iostreams PUBLIC
      thirdparty_lzma
    )
  endif()

  target_link_libraries(thirdparty_boost_iostreams PRIVATE
    thirdparty_cxx_settings
  )
endfunction()

boostMain()

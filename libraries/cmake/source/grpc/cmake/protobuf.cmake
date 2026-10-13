# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)


function(protobufMain)
  # Use library_root from parent scope if available (patched source), otherwise use direct path
  if(DEFINED library_root)
    set(protobuf_SOURCE_DIR "${library_root}/third_party/protobuf")
  else()
    set(protobuf_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src/third_party/protobuf")
  endif()

  # Define source file lists for protobuf v4.31.1
  # Based on https://github.com/protocolbuffers/protobuf/blob/v4.31.1/src/file_lists.cmake

  set(libprotobuf_srcs
    ${protobuf_SOURCE_DIR}/src/google/protobuf/any.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/any.pb.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/api.pb.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/arena.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/arenastring.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/arenaz_sampler.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/descriptor.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/descriptor.pb.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/descriptor_database.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/duration.pb.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/dynamic_message.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/empty.pb.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/extension_set.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/extension_set_heavy.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/field_mask.pb.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/generated_enum_util.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/generated_message_bases.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/generated_message_reflection.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/generated_message_tctable_full.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/generated_message_tctable_gen.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/generated_message_tctable_lite.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/generated_message_util.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/implicit_weak_message.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/inlined_string_field.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/io/coded_stream.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/io/gzip_stream.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/io/io_win32.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/io/printer.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/io/strtod.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/io/tokenizer.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/io/zero_copy_stream.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/io/zero_copy_stream_impl.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/io/zero_copy_stream_impl_lite.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/json/internal/lexer.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/json/internal/parser.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/json/internal/unparser.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/json/internal/untyped_message.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/json/internal/writer.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/json/internal/zero_copy_buffered_stream.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/json/json.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/map.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/map_field.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/message.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/message_lite.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/parse_context.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/reflection_ops.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/repeated_field.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/repeated_ptr_field.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/service.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/source_context.pb.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/struct.pb.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/stubs/common.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/text_format.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/timestamp.pb.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/type.pb.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/unknown_field_set.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/util/delimited_message_util.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/util/field_comparator.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/util/field_mask_util.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/util/json_util.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/util/message_differencer.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/util/time_util.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/util/type_resolver_util.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/wire_format.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/wire_format_lite.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/wrappers.pb.cc
  )

  set(libprotoc_srcs
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/code_generator.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/command_line_interface.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/cpp/enum.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/cpp/extension.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/cpp/field.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/cpp/file.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/cpp/generator.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/cpp/helpers.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/cpp/message.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/cpp/padding_optimizer.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/cpp/parse_function_generator.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/cpp/service.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/csharp/csharp_doc_comment.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/csharp/csharp_enum.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/csharp/csharp_enum_field.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/csharp/csharp_field_base.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/csharp/csharp_generator.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/csharp/csharp_helpers.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/csharp/csharp_map_field.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/csharp/csharp_message.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/csharp/csharp_message_field.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/csharp/csharp_primitive_field.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/csharp/csharp_reflection_class.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/csharp/csharp_repeated_enum_field.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/csharp/csharp_repeated_message_field.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/csharp/csharp_repeated_primitive_field.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/csharp/csharp_source_generator_base.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/csharp/csharp_wrapper_field.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/java/context.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/java/doc_comment.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/java/enum.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/java/enum_field.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/java/enum_field_lite.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/java/enum_lite.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/java/extension.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/java/extension_lite.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/java/field.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/java/file.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/java/full/enum_field.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/java/full/make_field_gens.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/java/full/map_field.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/java/full/message.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/java/full/message_builder.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/java/full/message_field.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/java/full/primitive_field.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/java/full/service.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/java/full/string_field.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/java/generator.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/java/generator_factory.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/java/helpers.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/java/kotlin_generator.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/java/lite/enum_field.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/java/lite/make_field_gens.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/java/lite/map_field.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/java/lite/message.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/java/lite/message_builder.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/java/lite/message_field.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/java/lite/primitive_field.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/java/lite/string_field.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/java/map_field.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/java/message.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/java/message_builder.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/java/message_builder_lite.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/java/message_field.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/java/message_field_lite.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/java/message_lite.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/java/message_serialization.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/java/name_resolver.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/java/names.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/java/primitive_field.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/java/primitive_field_lite.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/java/service.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/java/shared_code_generator.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/java/string_field.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/java/string_field_lite.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/objectivec/enum.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/objectivec/enum_field.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/objectivec/extension.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/objectivec/field.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/objectivec/file.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/objectivec/generator.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/objectivec/helpers.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/objectivec/import_writer.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/objectivec/line_consumer.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/objectivec/map_field.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/objectivec/message.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/objectivec/message_field.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/objectivec/names.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/objectivec/oneof.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/objectivec/primitive_field.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/objectivec/text_format_decode_data.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/php/names.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/php/php_generator.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/plugin.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/plugin.pb.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/python/generator.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/python/helpers.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/python/pyi_generator.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/retention.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/ruby/ruby_generator.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/rust/accessors/accessors.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/rust/accessors/map.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/rust/accessors/repeated_field.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/rust/accessors/singular_message.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/rust/accessors/singular_scalar.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/rust/accessors/singular_string.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/rust/accessors/unsupported_field.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/rust/context.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/rust/enum.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/rust/generator.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/rust/message.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/rust/naming.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/rust/relative_path.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/subprocess.cc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/zip_writer.cc
  )

  set(libupb_srcs
    ${protobuf_SOURCE_DIR}/upb/base/status.c
    ${protobuf_SOURCE_DIR}/upb/hash/common.c
    ${protobuf_SOURCE_DIR}/upb/json/decode.c
    ${protobuf_SOURCE_DIR}/upb/json/encode.c
    ${protobuf_SOURCE_DIR}/upb/lex/atoi.c
    ${protobuf_SOURCE_DIR}/upb/lex/round_trip.c
    ${protobuf_SOURCE_DIR}/upb/lex/strtod.c
    ${protobuf_SOURCE_DIR}/upb/lex/unicode.c
    ${protobuf_SOURCE_DIR}/upb/mem/alloc.c
    ${protobuf_SOURCE_DIR}/upb/mem/arena.c
    ${protobuf_SOURCE_DIR}/upb/message/accessors.c
    ${protobuf_SOURCE_DIR}/upb/message/array.c
    ${protobuf_SOURCE_DIR}/upb/message/compare.c
    ${protobuf_SOURCE_DIR}/upb/message/copy.c
    ${protobuf_SOURCE_DIR}/upb/message/emap.c
    ${protobuf_SOURCE_DIR}/upb/message/internal/compare_unknown.c
    ${protobuf_SOURCE_DIR}/upb/message/internal/extension.c
    ${protobuf_SOURCE_DIR}/upb/message/map.c
    ${protobuf_SOURCE_DIR}/upb/message/map_sorter.c
    ${protobuf_SOURCE_DIR}/upb/message/merge.c
    ${protobuf_SOURCE_DIR}/upb/message/message.c
    ${protobuf_SOURCE_DIR}/upb/message/promote.c
    ${protobuf_SOURCE_DIR}/upb/mini_descriptor/build_enum.c
    ${protobuf_SOURCE_DIR}/upb/mini_descriptor/decode.c
    ${protobuf_SOURCE_DIR}/upb/mini_descriptor/internal/base92.c
    ${protobuf_SOURCE_DIR}/upb/mini_descriptor/internal/encode.c
    ${protobuf_SOURCE_DIR}/upb/mini_descriptor/link.c
    ${protobuf_SOURCE_DIR}/upb/mini_table/extension.c
    ${protobuf_SOURCE_DIR}/upb/mini_table/extension_registry.c
    ${protobuf_SOURCE_DIR}/upb/mini_table/field.c
    ${protobuf_SOURCE_DIR}/upb/mini_table/file.c
    ${protobuf_SOURCE_DIR}/upb/mini_table/internal/message.c
    ${protobuf_SOURCE_DIR}/upb/mini_table/message.c
    ${protobuf_SOURCE_DIR}/upb/reflection/def_pool.c
    ${protobuf_SOURCE_DIR}/upb/reflection/def_type.c
    ${protobuf_SOURCE_DIR}/upb/reflection/desc_state.c
    ${protobuf_SOURCE_DIR}/upb/reflection/enum_def.c
    ${protobuf_SOURCE_DIR}/upb/reflection/enum_reserved_range.c
    ${protobuf_SOURCE_DIR}/upb/reflection/enum_value_def.c
    ${protobuf_SOURCE_DIR}/upb/reflection/extension_range.c
    ${protobuf_SOURCE_DIR}/upb/reflection/field_def.c
    ${protobuf_SOURCE_DIR}/upb/reflection/file_def.c
    ${protobuf_SOURCE_DIR}/upb/reflection/internal/def_builder.c
    ${protobuf_SOURCE_DIR}/upb/reflection/internal/strdup2.c
    ${protobuf_SOURCE_DIR}/upb/reflection/message.c
    ${protobuf_SOURCE_DIR}/upb/reflection/message_def.c
    ${protobuf_SOURCE_DIR}/upb/reflection/message_reserved_range.c
    ${protobuf_SOURCE_DIR}/upb/reflection/method_def.c
    ${protobuf_SOURCE_DIR}/upb/reflection/oneof_def.c
    ${protobuf_SOURCE_DIR}/upb/reflection/service_def.c
    ${protobuf_SOURCE_DIR}/upb/text/encode.c
    ${protobuf_SOURCE_DIR}/upb/wire/decode.c
    ${protobuf_SOURCE_DIR}/upb/wire/decode_fast.c
    ${protobuf_SOURCE_DIR}/upb/wire/encode.c
    ${protobuf_SOURCE_DIR}/upb/wire/eps_copy_input_stream.c
    ${protobuf_SOURCE_DIR}/upb/wire/reader.c
  )

  # Build utf8_range and utf8_validity libraries required by protobuf v4.31.1
  # These are simple C/C++ libraries that validate UTF-8 strings
  add_library(utf8_validity
    ${protobuf_SOURCE_DIR}/third_party/utf8_range/utf8_range.c
  )

  # Protobuf v4.31.1 requires abseil-cpp headers
  set(abseil_include_dir "${CMAKE_CURRENT_SOURCE_DIR}/src/third_party/abseil-cpp")
  set(utf8_range_include_dir "${protobuf_SOURCE_DIR}/third_party/utf8_range")

  # Protobuf v4.31.1 uses upb (micro protobuf) internally
  # The cmake directory contains pre-generated upb headers needed for bootstrap
  set(upb_include_dir "${protobuf_SOURCE_DIR}/upb/reflection/cmake")

  target_include_directories(utf8_validity PUBLIC
    "${utf8_range_include_dir}"
  )

  # Build libupb (micro protobuf) required by protobuf v4.31.1
  # upb is a smaller, lighter-weight protobuf implementation
  set(bootstrap_cmake_dir ${protobuf_SOURCE_DIR}/upb/reflection/cmake)
  set(bootstrap_sources
    ${bootstrap_cmake_dir}/google/protobuf/descriptor.upb_minitable.c
  )

  add_library(libupb STATIC
    ${libupb_srcs}
    ${bootstrap_sources}
  )

  target_include_directories(libupb PUBLIC
    "${bootstrap_cmake_dir}"
    "${protobuf_SOURCE_DIR}"
  )

  target_link_libraries(libupb PRIVATE utf8_validity)

  # Also include libprotoc sources
  # Note: file_lists.cmake defines libprotobuf_srcs, libprotobuf_hdrs, libprotoc_srcs, libprotoc_hdrs

  add_library(thirdparty_protobuf
    ${libprotobuf_srcs}
    ${libprotoc_srcs}
  )

  target_compile_definitions(thirdparty_protobuf PRIVATE
    HAVE_PTHREAD
  )

  find_package(Threads REQUIRED)

  # Protobuf v4.31.1 requires linking against Abseil libraries
  # These libraries should already be built by gRPC's add_subdirectory
  set(protobuf_ABSL_USED_TARGETS
    absl::absl_check
    absl::absl_log
    absl::algorithm
    absl::base
    absl::bind_front
    absl::bits
    absl::btree
    absl::cleanup
    absl::cord
    absl::core_headers
    absl::debugging
    absl::die_if_null
    absl::dynamic_annotations
    absl::flags
    absl::flat_hash_map
    absl::flat_hash_set
    absl::function_ref
    absl::hash
    absl::layout
    absl::log_initialize
    absl::log_globals
    absl::log_severity
    absl::memory
    absl::node_hash_map
    absl::node_hash_set
    absl::optional
    absl::random_distributions
    absl::random_random
    absl::span
    absl::status
    absl::statusor
    absl::strings
    absl::synchronization
    absl::time
    absl::type_traits
    absl::utility
  )

  target_link_libraries(thirdparty_protobuf PUBLIC
    Threads::Threads
    thirdparty_zlib
    utf8_validity
    libupb
    ${protobuf_ABSL_USED_TARGETS}
  )

  target_link_libraries(thirdparty_protobuf PRIVATE
    thirdparty_cxx_settings
  )

  target_include_directories(thirdparty_protobuf PRIVATE
    "${protobuf_SOURCE_DIR}"
    "${protobuf_SOURCE_DIR}/src"
    "${abseil_include_dir}"
    "${utf8_range_include_dir}"
    "${upb_include_dir}"
  )

  target_include_directories(thirdparty_protobuf SYSTEM INTERFACE
    "${protobuf_SOURCE_DIR}"
    "${protobuf_SOURCE_DIR}/src"
    "${abseil_include_dir}"
    "${utf8_range_include_dir}"
    "${upb_include_dir}"
  )

  add_executable(protoc
    ${protobuf_SOURCE_DIR}/src/google/protobuf/compiler/main.cc
  )

  target_include_directories(protoc PRIVATE
    "${protobuf_SOURCE_DIR}"
    "${protobuf_SOURCE_DIR}/src"
    "${abseil_include_dir}"
    "${utf8_range_include_dir}"
    "${upb_include_dir}"
  )

  target_link_libraries(protoc PRIVATE
    thirdparty_cxx_settings
    Threads::Threads
    thirdparty_protobuf
  )

  add_executable(protobuf::protoc ALIAS protoc)
endfunction()

protobufMain()

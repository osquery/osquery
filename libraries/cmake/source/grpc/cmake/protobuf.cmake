# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(protobufMain)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src/third_party/protobuf/")

  add_library(thirdparty_protobuf
    # libprotobuf_lite
    ${library_root}/src/google/protobuf/any_lite.cc
    ${library_root}/src/google/protobuf/arena.cc
    ${library_root}/src/google/protobuf/arenastring.cc
    ${library_root}/src/google/protobuf/arenaz_sampler.cc
    ${library_root}/src/google/protobuf/extension_set.cc
    #${library_root}/src/google/protobuf/generated_enum_util.cc
    ${library_root}/src/google/protobuf/generated_message_tctable_lite.cc
    ${library_root}/src/google/protobuf/generated_message_util.cc
    ${library_root}/src/google/protobuf/implicit_weak_message.cc
    ${library_root}/src/google/protobuf/inlined_string_field.cc
    ${library_root}/src/google/protobuf/io/coded_stream.cc
    ${library_root}/src/google/protobuf/io/io_win32.cc
    ${library_root}/src/google/protobuf/io/strtod.cc
    ${library_root}/src/google/protobuf/io/zero_copy_stream.cc
    ${library_root}/src/google/protobuf/io/zero_copy_stream_impl.cc
    ${library_root}/src/google/protobuf/io/zero_copy_stream_impl_lite.cc
    ${library_root}/src/google/protobuf/map.cc
    ${library_root}/src/google/protobuf/message_lite.cc
    ${library_root}/src/google/protobuf/parse_context.cc
    ${library_root}/src/google/protobuf/repeated_field.cc
    ${library_root}/src/google/protobuf/repeated_ptr_field.cc
    ${library_root}/src/google/protobuf/stubs/bytestream.cc
    ${library_root}/src/google/protobuf/stubs/common.cc
    ${library_root}/src/google/protobuf/stubs/int128.cc
    ${library_root}/src/google/protobuf/stubs/status.cc
    ${library_root}/src/google/protobuf/stubs/statusor.cc
    ${library_root}/src/google/protobuf/stubs/stringpiece.cc
    ${library_root}/src/google/protobuf/stubs/stringprintf.cc
    ${library_root}/src/google/protobuf/stubs/structurally_valid.cc
    ${library_root}/src/google/protobuf/stubs/strutil.cc
    ${library_root}/src/google/protobuf/stubs/time.cc
    ${library_root}/src/google/protobuf/wire_format_lite.cc
    ${library_root}/src/google/protobuf/any_lite.cc
    ${library_root}/src/google/protobuf/arena.cc

    # libprotobuf
    ${library_root}/src/google/protobuf/any.cc
    ${library_root}/src/google/protobuf/any.pb.cc
    ${library_root}/src/google/protobuf/api.pb.cc
    ${library_root}/src/google/protobuf/compiler/importer.cc
    ${library_root}/src/google/protobuf/compiler/parser.cc
    ${library_root}/src/google/protobuf/descriptor.cc
    ${library_root}/src/google/protobuf/descriptor.pb.cc
    ${library_root}/src/google/protobuf/descriptor_database.cc
    ${library_root}/src/google/protobuf/duration.pb.cc
    ${library_root}/src/google/protobuf/dynamic_message.cc
    ${library_root}/src/google/protobuf/empty.pb.cc
    ${library_root}/src/google/protobuf/extension_set_heavy.cc
    ${library_root}/src/google/protobuf/field_mask.pb.cc
    ${library_root}/src/google/protobuf/generated_message_bases.cc
    ${library_root}/src/google/protobuf/generated_message_reflection.cc
    ${library_root}/src/google/protobuf/generated_message_tctable_full.cc
    ${library_root}/src/google/protobuf/io/gzip_stream.cc
    ${library_root}/src/google/protobuf/io/printer.cc
    ${library_root}/src/google/protobuf/io/tokenizer.cc
    ${library_root}/src/google/protobuf/map_field.cc
    ${library_root}/src/google/protobuf/message.cc
    ${library_root}/src/google/protobuf/reflection_ops.cc
    ${library_root}/src/google/protobuf/service.cc
    ${library_root}/src/google/protobuf/source_context.pb.cc
    ${library_root}/src/google/protobuf/struct.pb.cc
    ${library_root}/src/google/protobuf/stubs/substitute.cc
    ${library_root}/src/google/protobuf/text_format.cc
    ${library_root}/src/google/protobuf/timestamp.pb.cc
    ${library_root}/src/google/protobuf/type.pb.cc
    ${library_root}/src/google/protobuf/unknown_field_set.cc
    ${library_root}/src/google/protobuf/util/delimited_message_util.cc
    ${library_root}/src/google/protobuf/util/field_comparator.cc
    ${library_root}/src/google/protobuf/util/field_mask_util.cc
    ${library_root}/src/google/protobuf/util/internal/datapiece.cc
    ${library_root}/src/google/protobuf/util/internal/default_value_objectwriter.cc
    ${library_root}/src/google/protobuf/util/internal/error_listener.cc
    ${library_root}/src/google/protobuf/util/internal/field_mask_utility.cc
    ${library_root}/src/google/protobuf/util/internal/json_escaping.cc
    ${library_root}/src/google/protobuf/util/internal/json_objectwriter.cc
    ${library_root}/src/google/protobuf/util/internal/json_stream_parser.cc
    ${library_root}/src/google/protobuf/util/internal/object_writer.cc
    ${library_root}/src/google/protobuf/util/internal/proto_writer.cc
    ${library_root}/src/google/protobuf/util/internal/protostream_objectsource.cc
    ${library_root}/src/google/protobuf/util/internal/protostream_objectwriter.cc
    ${library_root}/src/google/protobuf/util/internal/type_info.cc
    ${library_root}/src/google/protobuf/util/internal/utility.cc
    ${library_root}/src/google/protobuf/util/json_util.cc
    ${library_root}/src/google/protobuf/util/message_differencer.cc
    ${library_root}/src/google/protobuf/util/time_util.cc
    ${library_root}/src/google/protobuf/util/type_resolver_util.cc
    ${library_root}/src/google/protobuf/wire_format.cc
    ${library_root}/src/google/protobuf/wrappers.pb.cc
        
    # libprotoc
    ${library_root}/src/google/protobuf/compiler/code_generator.cc
    ${library_root}/src/google/protobuf/compiler/command_line_interface.cc
    ${library_root}/src/google/protobuf/compiler/cpp/enum.cc
    ${library_root}/src/google/protobuf/compiler/cpp/enum_field.cc
    ${library_root}/src/google/protobuf/compiler/cpp/extension.cc
    ${library_root}/src/google/protobuf/compiler/cpp/field.cc
    ${library_root}/src/google/protobuf/compiler/cpp/file.cc
    ${library_root}/src/google/protobuf/compiler/cpp/generator.cc
    ${library_root}/src/google/protobuf/compiler/cpp/helpers.cc
    ${library_root}/src/google/protobuf/compiler/cpp/map_field.cc
    ${library_root}/src/google/protobuf/compiler/cpp/message.cc
    ${library_root}/src/google/protobuf/compiler/cpp/message_field.cc
    ${library_root}/src/google/protobuf/compiler/cpp/padding_optimizer.cc
    ${library_root}/src/google/protobuf/compiler/cpp/parse_function_generator.cc
    ${library_root}/src/google/protobuf/compiler/cpp/primitive_field.cc
    ${library_root}/src/google/protobuf/compiler/cpp/service.cc
    ${library_root}/src/google/protobuf/compiler/cpp/string_field.cc
    ${library_root}/src/google/protobuf/compiler/csharp/csharp_doc_comment.cc
    ${library_root}/src/google/protobuf/compiler/csharp/csharp_enum.cc
    ${library_root}/src/google/protobuf/compiler/csharp/csharp_enum_field.cc
    ${library_root}/src/google/protobuf/compiler/csharp/csharp_field_base.cc
    ${library_root}/src/google/protobuf/compiler/csharp/csharp_generator.cc
    ${library_root}/src/google/protobuf/compiler/csharp/csharp_helpers.cc
    ${library_root}/src/google/protobuf/compiler/csharp/csharp_map_field.cc
    ${library_root}/src/google/protobuf/compiler/csharp/csharp_message.cc
    ${library_root}/src/google/protobuf/compiler/csharp/csharp_message_field.cc
    ${library_root}/src/google/protobuf/compiler/csharp/csharp_primitive_field.cc
    ${library_root}/src/google/protobuf/compiler/csharp/csharp_reflection_class.cc
    ${library_root}/src/google/protobuf/compiler/csharp/csharp_repeated_enum_field.cc
    ${library_root}/src/google/protobuf/compiler/csharp/csharp_repeated_message_field.cc
    ${library_root}/src/google/protobuf/compiler/csharp/csharp_repeated_primitive_field.cc
    ${library_root}/src/google/protobuf/compiler/csharp/csharp_source_generator_base.cc
    ${library_root}/src/google/protobuf/compiler/csharp/csharp_wrapper_field.cc
    ${library_root}/src/google/protobuf/compiler/java/context.cc
    ${library_root}/src/google/protobuf/compiler/java/doc_comment.cc
    ${library_root}/src/google/protobuf/compiler/java/enum.cc
    ${library_root}/src/google/protobuf/compiler/java/enum_field.cc
    ${library_root}/src/google/protobuf/compiler/java/enum_field_lite.cc
    ${library_root}/src/google/protobuf/compiler/java/enum_lite.cc
    ${library_root}/src/google/protobuf/compiler/java/extension.cc
    ${library_root}/src/google/protobuf/compiler/java/extension_lite.cc
    ${library_root}/src/google/protobuf/compiler/java/field.cc
    ${library_root}/src/google/protobuf/compiler/java/file.cc
    ${library_root}/src/google/protobuf/compiler/java/generator.cc
    ${library_root}/src/google/protobuf/compiler/java/generator_factory.cc
    ${library_root}/src/google/protobuf/compiler/java/helpers.cc
    ${library_root}/src/google/protobuf/compiler/java/kotlin_generator.cc
    ${library_root}/src/google/protobuf/compiler/java/map_field.cc
    ${library_root}/src/google/protobuf/compiler/java/map_field_lite.cc
    ${library_root}/src/google/protobuf/compiler/java/message.cc
    ${library_root}/src/google/protobuf/compiler/java/message_builder.cc
    ${library_root}/src/google/protobuf/compiler/java/message_builder_lite.cc
    ${library_root}/src/google/protobuf/compiler/java/message_field.cc
    ${library_root}/src/google/protobuf/compiler/java/message_field_lite.cc
    ${library_root}/src/google/protobuf/compiler/java/message_lite.cc
    ${library_root}/src/google/protobuf/compiler/java/name_resolver.cc
    ${library_root}/src/google/protobuf/compiler/java/primitive_field.cc
    ${library_root}/src/google/protobuf/compiler/java/primitive_field_lite.cc
    ${library_root}/src/google/protobuf/compiler/java/service.cc
    ${library_root}/src/google/protobuf/compiler/java/shared_code_generator.cc
    ${library_root}/src/google/protobuf/compiler/java/string_field.cc
    ${library_root}/src/google/protobuf/compiler/java/string_field_lite.cc
    ${library_root}/src/google/protobuf/compiler/objectivec/objectivec_enum.cc
    ${library_root}/src/google/protobuf/compiler/objectivec/objectivec_enum_field.cc
    ${library_root}/src/google/protobuf/compiler/objectivec/objectivec_extension.cc
    ${library_root}/src/google/protobuf/compiler/objectivec/objectivec_field.cc
    ${library_root}/src/google/protobuf/compiler/objectivec/objectivec_file.cc
    ${library_root}/src/google/protobuf/compiler/objectivec/objectivec_generator.cc
    ${library_root}/src/google/protobuf/compiler/objectivec/objectivec_helpers.cc
    ${library_root}/src/google/protobuf/compiler/objectivec/objectivec_map_field.cc
    ${library_root}/src/google/protobuf/compiler/objectivec/objectivec_message.cc
    ${library_root}/src/google/protobuf/compiler/objectivec/objectivec_message_field.cc
    ${library_root}/src/google/protobuf/compiler/objectivec/objectivec_oneof.cc
    ${library_root}/src/google/protobuf/compiler/objectivec/objectivec_primitive_field.cc
    ${library_root}/src/google/protobuf/compiler/php/php_generator.cc
    ${library_root}/src/google/protobuf/compiler/plugin.cc
    ${library_root}/src/google/protobuf/compiler/plugin.pb.cc
    ${library_root}/src/google/protobuf/compiler/python/generator.cc
    ${library_root}/src/google/protobuf/compiler/python/helpers.cc
    ${library_root}/src/google/protobuf/compiler/python/pyi_generator.cc
    ${library_root}/src/google/protobuf/compiler/ruby/ruby_generator.cc
    ${library_root}/src/google/protobuf/compiler/subprocess.cc
    ${library_root}/src/google/protobuf/compiler/zip_writer.cc
  )

  target_compile_definitions(thirdparty_protobuf PRIVATE
    HAVE_PTHREAD
  )

  find_package(Threads REQUIRED)

  target_link_libraries(thirdparty_protobuf PUBLIC
    Threads::Threads
    thirdparty_zlib
  )

  target_link_libraries(thirdparty_protobuf PRIVATE
    thirdparty_cxx_settings
  )

  target_include_directories(thirdparty_protobuf PRIVATE
    "${library_root}"
    "${library_root}/src"
  )

  target_include_directories(thirdparty_protobuf SYSTEM INTERFACE
    "${library_root}"
    "${library_root}/src"
  )

  add_executable(protoc
    ${library_root}/src/google/protobuf/compiler/main.cc
  )
  
  target_include_directories(protoc PRIVATE
    "${library_root}"
    "${library_root}/src"
  )

  target_link_libraries(protoc PRIVATE
    thirdparty_cxx_settings
    Threads::Threads
    thirdparty_protobuf
  )

  add_executable(protobuf::protoc ALIAS protoc)
endfunction()

protobufMain()
# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(rocksdbMain)
  if(NOT DEFINED PLATFORM_LINUX AND NOT DEFINED PLATFORM_MACOS AND
     NOT DEFINED PLATFORM_WINDOWS)
    add_osquery_library(thirdparty_rocksdb INTERFACE)
    return()
  endif()

  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")

  add_library(thirdparty_rocksdb
    "${CMAKE_CURRENT_SOURCE_DIR}/version/build_version.cc"
    "${library_root}/cache/clock_cache.cc"
    "${library_root}/cache/lru_cache.cc"
    "${library_root}/cache/sharded_cache.cc"
    "${library_root}/db/builder.cc"
    "${library_root}/db/c.cc"
    "${library_root}/db/column_family.cc"
    "${library_root}/db/compacted_db_impl.cc"
    "${library_root}/db/compaction.cc"
    "${library_root}/db/compaction_iterator.cc"
    "${library_root}/db/compaction_job.cc"
    "${library_root}/db/compaction_picker.cc"
    "${library_root}/db/compaction_picker_universal.cc"
    "${library_root}/db/convenience.cc"
    "${library_root}/db/db_filesnapshot.cc"
    "${library_root}/db/db_impl.cc"
    "${library_root}/db/db_impl_write.cc"
    "${library_root}/db/db_impl_compaction_flush.cc"
    "${library_root}/db/db_impl_files.cc"
    "${library_root}/db/db_impl_open.cc"
    "${library_root}/db/db_impl_debug.cc"
    "${library_root}/db/db_impl_experimental.cc"
    "${library_root}/db/db_impl_readonly.cc"
    "${library_root}/db/db_info_dumper.cc"
    "${library_root}/db/db_iter.cc"
    "${library_root}/db/dbformat.cc"
    "${library_root}/db/event_helpers.cc"
    "${library_root}/db/experimental.cc"
    "${library_root}/db/external_sst_file_ingestion_job.cc"
    "${library_root}/db/file_indexer.cc"
    "${library_root}/db/flush_job.cc"
    "${library_root}/db/flush_scheduler.cc"
    "${library_root}/db/forward_iterator.cc"
    "${library_root}/db/internal_stats.cc"
    "${library_root}/db/log_reader.cc"
    "${library_root}/db/log_writer.cc"
    "${library_root}/db/malloc_stats.cc"
    "${library_root}/db/managed_iterator.cc"
    "${library_root}/db/memtable.cc"
    "${library_root}/db/memtable_list.cc"
    "${library_root}/db/merge_helper.cc"
    "${library_root}/db/merge_operator.cc"
    "${library_root}/db/range_del_aggregator.cc"
    "${library_root}/db/repair.cc"
    "${library_root}/db/snapshot_impl.cc"
    "${library_root}/db/table_cache.cc"
    "${library_root}/db/table_properties_collector.cc"
    "${library_root}/db/transaction_log_impl.cc"
    "${library_root}/db/version_builder.cc"
    "${library_root}/db/version_edit.cc"
    "${library_root}/db/version_set.cc"
    "${library_root}/db/wal_manager.cc"
    "${library_root}/db/write_batch.cc"
    "${library_root}/db/write_batch_base.cc"
    "${library_root}/db/write_controller.cc"
    "${library_root}/db/write_thread.cc"
    "${library_root}/env/env.cc"
    "${library_root}/env/env_chroot.cc"
    "${library_root}/env/env_encryption.cc"
    "${library_root}/env/env_hdfs.cc"
    "${library_root}/env/mock_env.cc"
    "${library_root}/memtable/alloc_tracker.cc"
    "${library_root}/memtable/hash_cuckoo_rep.cc"
    "${library_root}/memtable/hash_linklist_rep.cc"
    "${library_root}/memtable/hash_skiplist_rep.cc"
    "${library_root}/memtable/skiplistrep.cc"
    "${library_root}/memtable/vectorrep.cc"
    "${library_root}/memtable/write_buffer_manager.cc"
    "${library_root}/monitoring/histogram.cc"
    "${library_root}/monitoring/histogram_windowing.cc"
    "${library_root}/monitoring/instrumented_mutex.cc"
    "${library_root}/monitoring/iostats_context.cc"
    "${library_root}/monitoring/perf_context.cc"
    "${library_root}/monitoring/perf_level.cc"
    "${library_root}/monitoring/statistics.cc"
    "${library_root}/monitoring/thread_status_impl.cc"
    "${library_root}/monitoring/thread_status_updater.cc"
    "${library_root}/monitoring/thread_status_util.cc"
    "${library_root}/monitoring/thread_status_util_debug.cc"
    "${library_root}/options/cf_options.cc"
    "${library_root}/options/db_options.cc"
    "${library_root}/options/options.cc"
    "${library_root}/options/options_helper.cc"
    "${library_root}/options/options_parser.cc"
    "${library_root}/options/options_sanity_check.cc"
    "${library_root}/port/stack_trace.cc"
    "${library_root}/table/adaptive_table_factory.cc"
    "${library_root}/table/block.cc"
    "${library_root}/table/block_based_filter_block.cc"
    "${library_root}/table/block_based_table_builder.cc"
    "${library_root}/table/block_based_table_factory.cc"
    "${library_root}/table/block_based_table_reader.cc"
    "${library_root}/table/block_builder.cc"
    "${library_root}/table/block_prefix_index.cc"
    "${library_root}/table/bloom_block.cc"
    "${library_root}/table/cuckoo_table_builder.cc"
    "${library_root}/table/cuckoo_table_factory.cc"
    "${library_root}/table/cuckoo_table_reader.cc"
    "${library_root}/table/flush_block_policy.cc"
    "${library_root}/table/format.cc"
    "${library_root}/table/full_filter_block.cc"
    "${library_root}/table/get_context.cc"
    "${library_root}/table/index_builder.cc"
    "${library_root}/table/iterator.cc"
    "${library_root}/table/merging_iterator.cc"
    "${library_root}/table/meta_blocks.cc"
    "${library_root}/table/partitioned_filter_block.cc"
    "${library_root}/table/persistent_cache_helper.cc"
    "${library_root}/table/plain_table_builder.cc"
    "${library_root}/table/plain_table_factory.cc"
    "${library_root}/table/plain_table_index.cc"
    "${library_root}/table/plain_table_key_coding.cc"
    "${library_root}/table/plain_table_reader.cc"
    "${library_root}/table/sst_file_writer.cc"
    "${library_root}/table/table_properties.cc"
    "${library_root}/table/two_level_iterator.cc"
    "${library_root}/tools/db_bench_tool.cc"
    "${library_root}/tools/dump/db_dump_tool.cc"
    "${library_root}/tools/ldb_cmd.cc"
    "${library_root}/tools/ldb_tool.cc"
    "${library_root}/tools/sst_dump_tool.cc"
    "${library_root}/util/arena.cc"
    "${library_root}/util/auto_roll_logger.cc"
    "${library_root}/util/bloom.cc"
    "${library_root}/util/coding.cc"
    "${library_root}/util/compaction_job_stats_impl.cc"
    "${library_root}/util/comparator.cc"
    "${library_root}/util/concurrent_arena.cc"
    "${library_root}/util/crc32c.cc"
    "${library_root}/util/delete_scheduler.cc"
    "${library_root}/util/dynamic_bloom.cc"
    "${library_root}/util/event_logger.cc"
    "${library_root}/util/file_reader_writer.cc"
    "${library_root}/util/file_util.cc"
    "${library_root}/util/filename.cc"
    "${library_root}/util/filter_policy.cc"
    "${library_root}/util/hash.cc"
    "${library_root}/util/log_buffer.cc"
    "${library_root}/util/murmurhash.cc"
    "${library_root}/util/random.cc"
    "${library_root}/util/rate_limiter.cc"
    "${library_root}/util/slice.cc"
    "${library_root}/util/sst_file_manager_impl.cc"
    "${library_root}/util/status.cc"
    "${library_root}/util/status_message.cc"
    "${library_root}/util/string_util.cc"
    "${library_root}/util/sync_point.cc"
    "${library_root}/util/testutil.cc"
    "${library_root}/util/thread_local.cc"
    "${library_root}/util/threadpool_imp.cc"
    "${library_root}/util/transaction_test_util.cc"
    "${library_root}/util/xxhash.cc"
    "${library_root}/utilities/backupable/backupable_db.cc"
    "${library_root}/utilities/blob_db/blob_db.cc"
    "${library_root}/utilities/blob_db/blob_db_impl.cc"
    "${library_root}/utilities/blob_db/blob_db_options_impl.cc"
    "${library_root}/utilities/blob_db/blob_dump_tool.cc"
    "${library_root}/utilities/blob_db/blob_file.cc"
    "${library_root}/utilities/blob_db/blob_log_reader.cc"
    "${library_root}/utilities/blob_db/blob_log_writer.cc"
    "${library_root}/utilities/blob_db/blob_log_format.cc"
    "${library_root}/utilities/blob_db/ttl_extractor.cc"
    "${library_root}/utilities/checkpoint/checkpoint_impl.cc"
    "${library_root}/utilities/col_buf_decoder.cc"
    "${library_root}/utilities/col_buf_encoder.cc"
    "${library_root}/utilities/column_aware_encoding_util.cc"
    "${library_root}/utilities/compaction_filters/remove_emptyvalue_compactionfilter.cc"
    "${library_root}/utilities/date_tiered/date_tiered_db_impl.cc"
    "${library_root}/utilities/debug.cc"
    "${library_root}/utilities/document/document_db.cc"
    "${library_root}/utilities/document/json_document.cc"
    "${library_root}/utilities/document/json_document_builder.cc"
    "${library_root}/utilities/env_mirror.cc"
    "${library_root}/utilities/env_timed.cc"
    "${library_root}/utilities/geodb/geodb_impl.cc"
    "${library_root}/utilities/leveldb_options/leveldb_options.cc"
    "${library_root}/utilities/lua/rocks_lua_compaction_filter.cc"
    "${library_root}/utilities/memory/memory_util.cc"
    "${library_root}/utilities/merge_operators/max.cc"
    "${library_root}/utilities/merge_operators/put.cc"
    "${library_root}/utilities/merge_operators/cassandra/format.cc"
    "${library_root}/utilities/merge_operators/cassandra/merge_operator.cc"
    "${library_root}/utilities/merge_operators/string_append/stringappend.cc"
    "${library_root}/utilities/merge_operators/string_append/stringappend2.cc"
    "${library_root}/utilities/merge_operators/uint64add.cc"
    "${library_root}/utilities/option_change_migration/option_change_migration.cc"
    "${library_root}/utilities/options/options_util.cc"
    "${library_root}/utilities/persistent_cache/block_cache_tier.cc"
    "${library_root}/utilities/persistent_cache/block_cache_tier_file.cc"
    "${library_root}/utilities/persistent_cache/block_cache_tier_metadata.cc"
    "${library_root}/utilities/persistent_cache/persistent_cache_tier.cc"
    "${library_root}/utilities/persistent_cache/volatile_tier_impl.cc"
    "${library_root}/utilities/redis/redis_lists.cc"
    "${library_root}/utilities/simulator_cache/sim_cache.cc"
    "${library_root}/utilities/spatialdb/spatial_db.cc"
    "${library_root}/utilities/table_properties_collectors/compact_on_deletion_collector.cc"
    "${library_root}/utilities/transactions/optimistic_transaction_db_impl.cc"
    "${library_root}/utilities/transactions/optimistic_transaction_impl.cc"
    "${library_root}/utilities/transactions/transaction_base.cc"
    "${library_root}/utilities/transactions/transaction_db_impl.cc"
    "${library_root}/utilities/transactions/transaction_db_mutex_impl.cc"
    "${library_root}/utilities/transactions/transaction_impl.cc"
    "${library_root}/utilities/transactions/transaction_lock_mgr.cc"
    "${library_root}/utilities/transactions/transaction_util.cc"
    "${library_root}/utilities/ttl/db_ttl_impl.cc"
    "${library_root}/utilities/write_batch_with_index/write_batch_with_index.cc"
    "${library_root}/utilities/write_batch_with_index/write_batch_with_index_internal.cc"
  )

  if(DEFINED PLATFORM_WINDOWS)
    target_sources(thirdparty_rocksdb PRIVATE
      "${library_root}/port/win/io_win.cc"
      "${library_root}/port/win/env_win.cc"
      "${library_root}/port/win/env_default.cc"
      "${library_root}/port/win/port_win.cc"
      "${library_root}/port/win/win_logger.cc"
      "${library_root}/port/win/win_thread.cc"
      "${library_root}/port/win/xpress_win.cc"
    )

  else()
    target_sources(thirdparty_rocksdb PRIVATE
      "${library_root}/port/port_posix.cc"
      "${library_root}/env/env_posix.cc"
      "${library_root}/env/io_posix.cc"
    )
  endif()

  if(DEFINED PLATFORM_MACOS)
    set(platform_definitions OS_MACOSX)

  elseif(DEFINED PLATFORM_LINUX)
    set(platform_definitions OS_LINUX)

  elseif(DEFINED PLATFORM_WINDOWS)
    set(platform_definitions
      WIN32
      OS_WIN
      _MBCS
      WIN64
      NOMINMAX
    )
  endif()

  if(DEFINED PLATFORM_POSIX)
    list(APPEND platform_definitions
      ROCKSDB_PLATFORM_POSIX
      ROCKSDB_LIB_IO_POSIX
    )
  endif()

  target_compile_definitions(thirdparty_rocksdb PRIVATE
    ROCKSDB_LITE
    ${platform_definitions}
  )

  target_link_libraries(thirdparty_rocksdb PUBLIC
    thirdparty_googletest
  )

  target_link_libraries(thirdparty_rocksdb PRIVATE
    thirdparty_cxx_settings
  )

  target_include_directories(thirdparty_rocksdb PRIVATE
    "${library_root}"
    "${library_root}/util"
    "${library_root}/include"
  )

  target_include_directories(thirdparty_rocksdb SYSTEM INTERFACE
    "${library_root}/include"
  )
endfunction()

rocksdbMain()

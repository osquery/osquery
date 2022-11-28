# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(rocksdbMain)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")
  set(crc32_impl "${library_root}/util/crc32c.cc")

  add_library(thirdparty_rocksdb
    "${CMAKE_CURRENT_SOURCE_DIR}/version/build_version.cc"

    "${crc32_impl}"
    "${library_root}/cache/cache.cc"
    "${library_root}/cache/cache_entry_roles.cc"
    "${library_root}/cache/clock_cache.cc"
    "${library_root}/cache/lru_cache.cc"
    "${library_root}/cache/sharded_cache.cc"
    "${library_root}/db/arena_wrapped_db_iter.cc"
    "${library_root}/db/blob/blob_fetcher.cc"
    "${library_root}/db/blob/blob_file_addition.cc"
    "${library_root}/db/blob/blob_file_builder.cc"
    "${library_root}/db/blob/blob_file_cache.cc"
    "${library_root}/db/blob/blob_file_garbage.cc"
    "${library_root}/db/blob/blob_file_meta.cc"
    "${library_root}/db/blob/blob_file_reader.cc"
    "${library_root}/db/blob/blob_log_format.cc"
    "${library_root}/db/blob/blob_log_sequential_reader.cc"
    "${library_root}/db/blob/blob_log_writer.cc"
    "${library_root}/db/builder.cc"
    "${library_root}/db/c.cc"
    "${library_root}/db/column_family.cc"
    "${library_root}/db/compaction/compaction.cc"
    "${library_root}/db/compaction/compaction_iterator.cc"
    "${library_root}/db/compaction/compaction_job.cc"
    "${library_root}/db/compaction/compaction_picker.cc"
    "${library_root}/db/compaction/compaction_picker_fifo.cc"
    "${library_root}/db/compaction/compaction_picker_level.cc"
    "${library_root}/db/compaction/compaction_picker_universal.cc"
    "${library_root}/db/compaction/sst_partitioner.cc"
    "${library_root}/db/convenience.cc"
    "${library_root}/db/db_filesnapshot.cc"
    "${library_root}/db/dbformat.cc"
    "${library_root}/db/db_impl/compacted_db_impl.cc"
    "${library_root}/db/db_impl/db_impl.cc"
    "${library_root}/db/db_impl/db_impl_compaction_flush.cc"
    "${library_root}/db/db_impl/db_impl_debug.cc"
    "${library_root}/db/db_impl/db_impl_experimental.cc"
    "${library_root}/db/db_impl/db_impl_files.cc"
    "${library_root}/db/db_impl/db_impl_open.cc"
    "${library_root}/db/db_impl/db_impl_readonly.cc"
    "${library_root}/db/db_impl/db_impl_secondary.cc"
    "${library_root}/db/db_impl/db_impl_write.cc"
    "${library_root}/db/db_info_dumper.cc"
    "${library_root}/db/db_iter.cc"
    "${library_root}/db/error_handler.cc"
    "${library_root}/db/event_helpers.cc"
    "${library_root}/db/experimental.cc"
    "${library_root}/db/external_sst_file_ingestion_job.cc"
    "${library_root}/db/file_indexer.cc"
    "${library_root}/db/flush_job.cc"
    "${library_root}/db/flush_scheduler.cc"
    "${library_root}/db/forward_iterator.cc"
    "${library_root}/db/import_column_family_job.cc"
    "${library_root}/db/internal_stats.cc"
    "${library_root}/db/log_reader.cc"
    "${library_root}/db/logs_with_prep_tracker.cc"
    "${library_root}/db/log_writer.cc"
    "${library_root}/db/malloc_stats.cc"
    "${library_root}/db/memtable.cc"
    "${library_root}/db/memtable_list.cc"
    "${library_root}/db/merge_helper.cc"
    "${library_root}/db/merge_operator.cc"
    "${library_root}/db/output_validator.cc"
    "${library_root}/db/periodic_work_scheduler.cc"
    "${library_root}/db/range_del_aggregator.cc"
    "${library_root}/db/range_tombstone_fragmenter.cc"
    "${library_root}/db/repair.cc"
    "${library_root}/db/snapshot_impl.cc"
    "${library_root}/db/table_cache.cc"
    "${library_root}/db/table_properties_collector.cc"
    "${library_root}/db/transaction_log_impl.cc"
    "${library_root}/db/trim_history_scheduler.cc"
    "${library_root}/db/version_builder.cc"
    "${library_root}/db/version_edit.cc"
    "${library_root}/db/version_edit_handler.cc"
    "${library_root}/db/version_set.cc"
    "${library_root}/db/wal_edit.cc"
    "${library_root}/db/wal_manager.cc"
    "${library_root}/db/write_batch_base.cc"
    "${library_root}/db/write_batch.cc"
    "${library_root}/db/write_controller.cc"
    "${library_root}/db/write_thread.cc"
    "${library_root}/env/composite_env.cc"
    "${library_root}/env/env.cc"
    "${library_root}/env/env_chroot.cc"
    "${library_root}/env/env_encryption.cc"
    "${library_root}/env/env_hdfs.cc"
    "${library_root}/env/file_system.cc"
    "${library_root}/env/file_system_tracer.cc"
    "${library_root}/env/fs_remap.cc"
    "${library_root}/env/mock_env.cc"
    "${library_root}/file/delete_scheduler.cc"
    "${library_root}/file/filename.cc"
    "${library_root}/file/file_prefetch_buffer.cc"
    "${library_root}/file/file_util.cc"
    "${library_root}/file/line_file_reader.cc"
    "${library_root}/file/random_access_file_reader.cc"
    "${library_root}/file/readahead_raf.cc"
    "${library_root}/file/read_write_util.cc"
    "${library_root}/file/sequence_file_reader.cc"
    "${library_root}/file/sst_file_manager_impl.cc"
    "${library_root}/file/writable_file_writer.cc"
    "${library_root}/logging/auto_roll_logger.cc"
    "${library_root}/logging/event_logger.cc"
    "${library_root}/logging/log_buffer.cc"
    "${library_root}/memory/arena.cc"
    "${library_root}/memory/concurrent_arena.cc"
    "${library_root}/memory/jemalloc_nodump_allocator.cc"
    "${library_root}/memory/memkind_kmem_allocator.cc"
    "${library_root}/memtable/alloc_tracker.cc"
    "${library_root}/memtable/hash_linklist_rep.cc"
    "${library_root}/memtable/hash_skiplist_rep.cc"
    "${library_root}/memtable/skiplistrep.cc"
    "${library_root}/memtable/vectorrep.cc"
    "${library_root}/memtable/write_buffer_manager.cc"
    "${library_root}/monitoring/histogram.cc"
    "${library_root}/monitoring/histogram_windowing.cc"
    "${library_root}/monitoring/in_memory_stats_history.cc"
    "${library_root}/monitoring/instrumented_mutex.cc"
    "${library_root}/monitoring/iostats_context.cc"
    "${library_root}/monitoring/perf_context.cc"
    "${library_root}/monitoring/perf_level.cc"
    "${library_root}/monitoring/persistent_stats_history.cc"
    "${library_root}/monitoring/statistics.cc"
    "${library_root}/monitoring/thread_status_impl.cc"
    "${library_root}/monitoring/thread_status_updater.cc"
    "${library_root}/monitoring/thread_status_util.cc"
    "${library_root}/monitoring/thread_status_util_debug.cc"
    "${library_root}/options/cf_options.cc"
    "${library_root}/options/configurable.cc"
    "${library_root}/options/customizable.cc"
    "${library_root}/options/db_options.cc"
    "${library_root}/options/options.cc"
    "${library_root}/options/options_helper.cc"
    "${library_root}/options/options_parser.cc"
    "${library_root}/port/stack_trace.cc"
    "${library_root}/table/adaptive/adaptive_table_factory.cc"
    "${library_root}/table/block_based/binary_search_index_reader.cc"
    "${library_root}/table/block_based/block_based_filter_block.cc"
    "${library_root}/table/block_based/block_based_table_builder.cc"
    "${library_root}/table/block_based/block_based_table_factory.cc"
    "${library_root}/table/block_based/block_based_table_iterator.cc"
    "${library_root}/table/block_based/block_based_table_reader.cc"
    "${library_root}/table/block_based/block_builder.cc"
    "${library_root}/table/block_based/block.cc"
    "${library_root}/table/block_based/block_prefetcher.cc"
    "${library_root}/table/block_based/block_prefix_index.cc"
    "${library_root}/table/block_based/data_block_footer.cc"
    "${library_root}/table/block_based/data_block_hash_index.cc"
    "${library_root}/table/block_based/filter_block_reader_common.cc"
    "${library_root}/table/block_based/filter_policy.cc"
    "${library_root}/table/block_based/flush_block_policy.cc"
    "${library_root}/table/block_based/full_filter_block.cc"
    "${library_root}/table/block_based/hash_index_reader.cc"
    "${library_root}/table/block_based/index_builder.cc"
    "${library_root}/table/block_based/index_reader_common.cc"
    "${library_root}/table/block_based/parsed_full_filter_block.cc"
    "${library_root}/table/block_based/partitioned_filter_block.cc"
    "${library_root}/table/block_based/partitioned_index_iterator.cc"
    "${library_root}/table/block_based/partitioned_index_reader.cc"
    "${library_root}/table/block_based/reader_common.cc"
    "${library_root}/table/block_based/uncompression_dict_reader.cc"
    "${library_root}/table/block_fetcher.cc"
    "${library_root}/table/cuckoo/cuckoo_table_builder.cc"
    "${library_root}/table/cuckoo/cuckoo_table_factory.cc"
    "${library_root}/table/cuckoo/cuckoo_table_reader.cc"
    "${library_root}/table/format.cc"
    "${library_root}/table/get_context.cc"
    "${library_root}/table/iterator.cc"
    "${library_root}/table/merging_iterator.cc"
    "${library_root}/table/meta_blocks.cc"
    "${library_root}/table/persistent_cache_helper.cc"
    "${library_root}/table/plain/plain_table_bloom.cc"
    "${library_root}/table/plain/plain_table_builder.cc"
    "${library_root}/table/plain/plain_table_factory.cc"
    "${library_root}/table/plain/plain_table_index.cc"
    "${library_root}/table/plain/plain_table_key_coding.cc"
    "${library_root}/table/plain/plain_table_reader.cc"
    "${library_root}/table/sst_file_dumper.cc"
    "${library_root}/table/sst_file_reader.cc"
    "${library_root}/table/sst_file_writer.cc"
    "${library_root}/table/table_factory.cc"
    "${library_root}/table/table_properties.cc"
    "${library_root}/table/two_level_iterator.cc"
    "${library_root}/test_util/sync_point.cc"
    "${library_root}/test_util/sync_point_impl.cc"
    "${library_root}/test_util/testutil.cc"
    "${library_root}/test_util/transaction_test_util.cc"
    "${library_root}/tools/block_cache_analyzer/block_cache_trace_analyzer.cc"
    "${library_root}/tools/dump/db_dump_tool.cc"
    "${library_root}/tools/io_tracer_parser_tool.cc"
    "${library_root}/tools/ldb_cmd.cc"
    "${library_root}/tools/ldb_tool.cc"
    "${library_root}/tools/sst_dump_tool.cc"
    "${library_root}/tools/trace_analyzer_tool.cc"
    "${library_root}/trace_replay/block_cache_tracer.cc"
    "${library_root}/trace_replay/io_tracer.cc"
    "${library_root}/trace_replay/trace_replay.cc"
    "${library_root}/util/coding.cc"
    "${library_root}/util/compaction_job_stats_impl.cc"
    "${library_root}/util/comparator.cc"
    "${library_root}/util/compression_context_cache.cc"
    "${library_root}/util/concurrent_task_limiter_impl.cc"
    "${library_root}/util/dynamic_bloom.cc"
    "${library_root}/util/file_checksum_helper.cc"
    "${library_root}/util/hash.cc"
    "${library_root}/utilities/backupable/backupable_db.cc"
    "${library_root}/utilities/blob_db/blob_compaction_filter.cc"
    "${library_root}/utilities/blob_db/blob_db.cc"
    "${library_root}/utilities/blob_db/blob_db_impl.cc"
    "${library_root}/utilities/blob_db/blob_db_impl_filesnapshot.cc"
    "${library_root}/utilities/blob_db/blob_dump_tool.cc"
    "${library_root}/utilities/blob_db/blob_file.cc"
    "${library_root}/utilities/cassandra/cassandra_compaction_filter.cc"
    "${library_root}/utilities/cassandra/format.cc"
    "${library_root}/utilities/cassandra/merge_operator.cc"
    "${library_root}/utilities/checkpoint/checkpoint_impl.cc"
    "${library_root}/utilities/compaction_filters/remove_emptyvalue_compactionfilter.cc"
    "${library_root}/utilities/debug.cc"
    "${library_root}/utilities/env_mirror.cc"
    "${library_root}/utilities/env_timed.cc"
    "${library_root}/utilities/fault_injection_env.cc"
    "${library_root}/utilities/fault_injection_fs.cc"
    "${library_root}/utilities/leveldb_options/leveldb_options.cc"
    "${library_root}/utilities/memory/memory_util.cc"
    "${library_root}/utilities/merge_operators/bytesxor.cc"
    "${library_root}/utilities/merge_operators/max.cc"
    "${library_root}/utilities/merge_operators/put.cc"
    "${library_root}/utilities/merge_operators/sortlist.cc"
    "${library_root}/utilities/merge_operators/string_append/stringappend2.cc"
    "${library_root}/utilities/merge_operators/string_append/stringappend.cc"
    "${library_root}/utilities/merge_operators/uint64add.cc"
    "${library_root}/utilities/object_registry.cc"
    "${library_root}/utilities/option_change_migration/option_change_migration.cc"
    "${library_root}/utilities/options/options_util.cc"
    "${library_root}/utilities/persistent_cache/block_cache_tier.cc"
    "${library_root}/utilities/persistent_cache/block_cache_tier_file.cc"
    "${library_root}/utilities/persistent_cache/block_cache_tier_metadata.cc"
    "${library_root}/utilities/persistent_cache/persistent_cache_tier.cc"
    "${library_root}/utilities/persistent_cache/volatile_tier_impl.cc"
    "${library_root}/utilities/simulator_cache/cache_simulator.cc"
    "${library_root}/utilities/simulator_cache/sim_cache.cc"
    "${library_root}/utilities/table_properties_collectors/compact_on_deletion_collector.cc"
    "${library_root}/utilities/trace/file_trace_reader_writer.cc"
    "${library_root}/utilities/transactions/lock/lock_manager.cc"
    "${library_root}/utilities/transactions/lock/point/point_lock_manager.cc"
    "${library_root}/utilities/transactions/lock/point/point_lock_tracker.cc"
    "${library_root}/utilities/transactions/lock/range/range_tree/lib/locktree/concurrent_tree.cc"
    "${library_root}/utilities/transactions/lock/range/range_tree/lib/locktree/keyrange.cc"
    "${library_root}/utilities/transactions/lock/range/range_tree/lib/locktree/lock_request.cc"
    "${library_root}/utilities/transactions/lock/range/range_tree/lib/locktree/locktree.cc"
    "${library_root}/utilities/transactions/lock/range/range_tree/lib/locktree/manager.cc"
    "${library_root}/utilities/transactions/lock/range/range_tree/lib/locktree/range_buffer.cc"
    "${library_root}/utilities/transactions/lock/range/range_tree/lib/locktree/treenode.cc"
    "${library_root}/utilities/transactions/lock/range/range_tree/lib/locktree/txnid_set.cc"
    "${library_root}/utilities/transactions/lock/range/range_tree/lib/locktree/wfg.cc"
    "${library_root}/utilities/transactions/lock/range/range_tree/lib/standalone_port.cc"
    "${library_root}/utilities/transactions/lock/range/range_tree/lib/util/dbt.cc"
    "${library_root}/utilities/transactions/lock/range/range_tree/lib/util/memarena.cc"
    "${library_root}/utilities/transactions/lock/range/range_tree/range_tree_lock_manager.cc"
    "${library_root}/utilities/transactions/lock/range/range_tree/range_tree_lock_tracker.cc"
    "${library_root}/utilities/transactions/optimistic_transaction.cc"
    "${library_root}/utilities/transactions/optimistic_transaction_db_impl.cc"
    "${library_root}/utilities/transactions/pessimistic_transaction.cc"
    "${library_root}/utilities/transactions/pessimistic_transaction_db.cc"
    "${library_root}/utilities/transactions/snapshot_checker.cc"
    "${library_root}/utilities/transactions/transaction_base.cc"
    "${library_root}/utilities/transactions/transaction_db_mutex_impl.cc"
    "${library_root}/utilities/transactions/transaction_util.cc"
    "${library_root}/utilities/transactions/write_prepared_txn.cc"
    "${library_root}/utilities/transactions/write_prepared_txn_db.cc"
    "${library_root}/utilities/transactions/write_unprepared_txn.cc"
    "${library_root}/utilities/transactions/write_unprepared_txn_db.cc"
    "${library_root}/utilities/ttl/db_ttl_impl.cc"
    "${library_root}/utilities/write_batch_with_index/write_batch_with_index.cc"
    "${library_root}/utilities/write_batch_with_index/write_batch_with_index_internal.cc"
    "${library_root}/util/murmurhash.cc"
    "${library_root}/util/random.cc"
    "${library_root}/util/rate_limiter.cc"
    "${library_root}/util/ribbon_config.cc"
    "${library_root}/util/slice.cc"
    "${library_root}/util/status.cc"
    "${library_root}/util/string_util.cc"
    "${library_root}/util/thread_local.cc"
    "${library_root}/util/threadpool_imp.cc"
    "${library_root}/util/xxhash.cc"
  )

  if(PLATFORM_POSIX)
    target_sources(thirdparty_rocksdb PRIVATE
      "${library_root}/env/env_posix.cc"
      "${library_root}/env/fs_posix.cc"
      "${library_root}/env/io_posix.cc"
      "${library_root}/port/port_posix.cc"
    )

  else()
    target_sources(thirdparty_rocksdb PRIVATE
      "${library_root}/port/win/env_default.cc"
      "${library_root}/port/win/env_win.cc"
      "${library_root}/port/win/io_win.cc"
      "${library_root}/port/win/port_win.cc"
      "${library_root}/port/win/win_logger.cc"
      "${library_root}/port/win/win_thread.cc"
    )
  endif()

  if(NOT PLATFORM_MACOS)
    target_sources(thirdparty_rocksdb PRIVATE
      "${library_root}/third-party/folly/folly/detail/Futex.cpp"
      "${library_root}/third-party/folly/folly/synchronization/AtomicNotification.cpp"
      "${library_root}/third-party/folly/folly/synchronization/DistributedMutex.cpp"
      "${library_root}/third-party/folly/folly/synchronization/ParkingLot.cpp"
      "${library_root}/third-party/folly/folly/synchronization/WaitOptions.cpp"
    )
  endif()

  if(TARGET_PROCESSOR STREQUAL "x86_64")
    if(NOT PLATFORM_WINDOWS)
      set_source_files_properties("${crc32_impl}" PROPERTIES
        COMPILE_FLAGS
          "-msse4.2 -mpclmul"
      )
    endif()

    target_compile_definitions(thirdparty_rocksdb PRIVATE
      HAVE_SSE42
    )

    # Enable PCLMUL only if we are on posix platforms, or on Windows 64bit
    if(DEFINED PLATFORM_POSIX OR (DEFINED PLATFORM_WINDOWS AND CMAKE_SIZEOF_VOID_P EQUAL 8))
      target_compile_definitions(thirdparty_rocksdb PRIVATE
        HAVE_PCLMUL
      )
    endif()

  elseif(TARGET_PROCESSOR STREQUAL "aarch64")
    target_sources(thirdparty_rocksdb PRIVATE
      "${library_root}/util/crc32c_arm64.cc"
    )
  endif()

  if(PLATFORM_LINUX)
    if(TARGET_PROCESSOR STREQUAL "x86_64")
      target_compile_definitions(thirdparty_rocksdb
        PUBLIC
          ROCKSDB_SUPPORT_THREAD_LOCAL

        PRIVATE
          NPERF_CONTEXT
          OS_LINUX
          ROCKSDB_FALLOCATE_PRESENT
          ROCKSDB_LIB_IO_POSIX
          ROCKSDB_MALLOC_USABLE_SIZE
          ROCKSDB_NO_DYNAMIC_EXTENSION
          ROCKSDB_PLATFORM_POSIX
          ROCKSDB_PTHREAD_ADAPTIVE_MUTEX
          ROCKSDB_RANGESYNC_PRESENT
          ROCKSDB_SCHED_GETCPU_PRESENT
      )

    elseif(TARGET_PROCESSOR STREQUAL "aarch64")
      target_compile_definitions(thirdparty_rocksdb PRIVATE
        NIOSTATS_CONTEXT
        NPERF_CONTEXT
        OS_LINUX
        ROCKSDB_LIB_IO_POSIX
        ROCKSDB_NO_DYNAMIC_EXTENSION
        ROCKSDB_PLATFORM_POSIX
      )
    endif()

  elseif(PLATFORM_MACOS)
    if(TARGET_PROCESSOR STREQUAL "x86_64")
      target_compile_definitions(thirdparty_rocksdb
        PUBLIC
          ROCKSDB_SUPPORT_THREAD_LOCAL

        PRIVATE
          NPERF_CONTEXT
          OS_MACOSX
          ROCKSDB_LIB_IO_POSIX
          ROCKSDB_NO_DYNAMIC_EXTENSION
          ROCKSDB_PLATFORM_POSIX
      )

    elseif(TARGET_PROCESSOR STREQUAL "aarch64")
      target_compile_definitions(thirdparty_rocksdb PRIVATE
        NIOSTATS_CONTEXT
        NPERF_CONTEXT
        OS_MACOSX
        ROCKSDB_LIB_IO_POSIX
        ROCKSDB_NO_DYNAMIC_EXTENSION
        ROCKSDB_PLATFORM_POSIX
      )
    endif()

  elseif(PLATFORM_WINDOWS)
    if(TARGET_PROCESSOR STREQUAL "x86_64")
      target_compile_definitions(thirdparty_rocksdb
        PUBLIC
          ROCKSDB_SUPPORT_THREAD_LOCAL
          OS_WIN

        PRIVATE
          _MBCS
          NOMINMAX
          NPERF_CONTEXT
          ROCKSDB_NO_DYNAMIC_EXTENSION
          WIN32
          WIN64
      )
    endif()
  endif()

  set(library_list)

  if(PLATFORM_LINUX)
    find_package(Threads REQUIRED)
    list(APPEND library_list
      Threads::Threads
    )

  elseif(PLATFORM_WINDOWS)
    list(APPEND library_list
      shlwapi.lib
      rpcrt4.lib
    )
  endif()

  target_link_libraries(thirdparty_rocksdb
    PRIVATE
      thirdparty_cxx_settings

    PUBLIC
      ${library_list}
  )

  target_include_directories(thirdparty_rocksdb PRIVATE
    "${library_root}"
    "${library_root}/include"
  )

  if(NOT PLATFORM_MACOS)
    target_include_directories(thirdparty_rocksdb PRIVATE
      "${library_root}/third-party/folly"
    )
  endif()

  target_include_directories(thirdparty_rocksdb SYSTEM INTERFACE
    "${library_root}/include"
  )

  if(PLATFORM_WINDOWS)
    # By defining this, we'll cause the WinEnvIO::AreFilesSame method to return
    # Status::NotSupported(), so that the caller can use a different way to
    # determine whether the files are matching. This lets us keep the project-wide
    # _WIN32_WINNT definition set to Windows 7 under cmake/flags.cmake.
    set_source_files_properties(
      "${library_root}/port/win/env_win.cc"
      PROPERTIES COMPILE_OPTIONS "/FI${CMAKE_CURRENT_SOURCE_DIR}/patches/env_win.h"
    )
  endif()
endfunction()

rocksdbMain()

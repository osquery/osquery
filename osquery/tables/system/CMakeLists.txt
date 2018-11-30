# Copyright (c) 2018-present, Trail of Bits, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION 3.13.1)

function(osquery_tables_system_main)
  generateOsqueryTablesSystem()
endfunction()

function(generateOsqueryTablesSystem)
  set(source_files
    cpuid.cpp
    hash.cpp
    python_packages.cpp
    system_utils.cpp
    uptime.cpp
  )

  if(DEFINED PLATFORM_POSIX)
    list(APPEND source_files
      posix/apt_sources.cpp
      posix/augeas.cpp
      posix/authorized_keys.cpp
      posix/crontab.cpp
      posix/known_hosts.cpp
      posix/last.cpp
      posix/load_average.cpp
      posix/logged_in_users.cpp
      posix/magic.cpp
      posix/shell_history.cpp
      posix/smbios_utils.cpp
      posix/ssh_configs.cpp
      posix/ssh_keys.cpp
      posix/sudoers.cpp
      posix/suid_bin.cpp
      posix/system_controls.cpp
      posix/ulimit_info.cpp
      posix/yum_sources.cpp
    )
  endif()

  if(DEFINED PLATFORM_LINUX)
    list(APPEND source_files
      freenux/cpu_time.cpp
      linux/acpi_tables.cpp
      linux/block_devices.cpp
      linux/deb_packages.cpp
      linux/disk_encryption.cpp
      linux/elf_info.cpp
      linux/groups.cpp
      linux/intel_me.cpp
      linux/kernel_info.cpp
      linux/kernel_integrity.cpp
      linux/kernel_modules.cpp
      linux/md_tables.cpp
      linux/memory_info.cpp
      linux/memory_map.cpp
      linux/model_specific_register.cpp
      linux/mounts.cpp
      linux/npm_packages.cpp
      linux/os_version.cpp
      linux/pci_devices.cpp
      linux/portage.cpp
      linux/process_open_files.cpp
      linux/processes.cpp
      linux/rpm_packages.cpp
      linux/shadow.cpp
      linux/shared_memory.cpp
      linux/smbios_tables.cpp
      linux/sysctl_utils.cpp
      linux/system_info.cpp
      linux/usb_devices.cpp
      linux/user_groups.cpp
      linux/users.cpp
    )

  elseif(DEFINED PLATFORM_MACOS)
    list(APPEND source_files
      darwin/account_policy_data.mm
      darwin/acpi_tables.cpp
      darwin/ad_config.cpp
      darwin/apps.mm
      darwin/asl.cpp
      darwin/asl_utils.cpp
      darwin/authorizations.mm
      darwin/battery.mm
      darwin/block_devices.cpp
      darwin/certificates.mm
      darwin/cpu_time.cpp
      darwin/crashes.cpp
      darwin/cups_destinations.cpp
      darwin/cups_jobs.cpp
      darwin/disk_encryption.mm
      darwin/event_taps.mm
      darwin/extended_attributes.cpp
      darwin/firewall.cpp
      darwin/gatekeeper.cpp
      darwin/homebrew_packages.cpp
      darwin/iokit_registry.cpp
      darwin/kernel_extensions.cpp
      darwin/kernel_info.cpp
      darwin/kernel_panics.cpp
      darwin/keychain_acl.cpp
      darwin/keychain_items.cpp
      darwin/keychain_utils.cpp
      darwin/launchd.cpp
      darwin/managed_policies.cpp
      darwin/mdfind.mm
      darwin/mounts.cpp
      darwin/nfs_shares.cpp
      darwin/nvram.cpp
      darwin/os_version.cpp
      darwin/packages.mm
      darwin/pci_devices.cpp
      darwin/preferences.cpp
      darwin/process_open_descriptors.cpp
      darwin/processes.cpp
      darwin/quicklook_cache.cpp
      darwin/running_apps.mm
      darwin/sandboxes.cpp
      darwin/shared_folders.mm
      darwin/sharing_preferences.cpp
      darwin/signature.mm
      darwin/sip_config.cpp
      darwin/smbios_tables.cpp
      darwin/smc_keys.cpp
      darwin/startup_items.cpp
      darwin/sysctl_utils.cpp
      darwin/system_info.cpp
      darwin/time_machine.cpp
      darwin/usb_devices.cpp
      darwin/user_groups.mm
      darwin/virtual_memory_info.cpp
      darwin/xprotect.cpp
    )

  elseif(DEFINED PLATFORM_FREEBSD)
    list(APPEND source_files
      freebsd/fbsd_kmods.cpp
      freebsd/groups.cpp
      freebsd/mounts.cpp
      freebsd/os_version.cpp
      freebsd/pkg_packages.cpp
      freebsd/process_open_files.cpp
      freebsd/processes.cpp
      freebsd/procstat.cpp
      freebsd/sysctl_utils.cpp
      freebsd/users.cpp
      freenux/cpu_time.cpp
    )

  elseif(DEFINED PLATFORM_WINDOWS)
    list(APPEND source_files
      windows/appcompat_shims.cpp
      windows/authenticode.cpp
      windows/autoexec.cpp
      windows/bitlocker_info.cpp
      windows/certificates.cpp
      windows/chocolatey_packages.cpp
      windows/cpu_info.cpp
      windows/disk_info.cpp
      windows/drivers.cpp
      windows/groups.cpp
      windows/ie_extensions.cpp
      windows/intel_me.cpp
      windows/kernel_info.cpp
      windows/kva_speculative_info.cpp
      windows/logged_in_users.cpp
      windows/logical_drives.cpp
      windows/logon_sessions.cpp
      windows/ntdomains.cpp
      windows/ntfs_acl_permissions.cpp
      windows/objects.cpp
      windows/os_version.cpp
      windows/patches.cpp
      windows/physical_disk_performance.cpp
      windows/pipes.cpp
      windows/processes.cpp
      windows/programs.cpp
      windows/registry.cpp
      windows/scheduled_tasks.cpp
      windows/services.cpp
      windows/shared_resources.cpp
      windows/smbios_tables.cpp
      windows/startup_items.cpp
      windows/system_info.cpp
      windows/user_groups.cpp
      windows/users.cpp
      windows/video_info.cpp
      windows/windows_crashes.cpp
      windows/wmi_bios_info.cpp
      windows/wmi_cli_event_consumers.cpp
      windows/wmi_event_filters.cpp
      windows/wmi_filter_consumer_binding.cpp
      windows/wmi_script_event_consumers.cpp
    )
  endif()

  add_library(osquery_tables_system EXCLUDE_FROM_ALL
    ${source_files}
  )

  target_link_libraries(osquery_tables_system PUBLIC
    global_cxx_settings
    osquery_headers
    osquery_core
    osquery_events
    osquery_filesystem
    osquery_hashing
    osquery_logger
    osquery_process
    osquery_sql
    osquery_utils
    osquery_utils_conversions
    osquery_utils_expected
    osquery_utils_system_filepath
    osquery_utils_system
    osquery_utils_system_time
    osquery_utils_system_uptime
    thirdparty_augeas
    thirdparty_boost
    thirdparty_libmagic
    thirdparty_libxml2
  )

  if(DEFINED PLATFORM_LINUX)
    target_link_libraries(osquery_tables_system PUBLIC
      thirdparty_libdevmapper
      thirdparty_libdpkg
      thirdparty_libelfin
      thirdparty_libcryptsetup
      thirdparty_librpm
      thirdparty_popt
    )

  elseif(DEFINED PLATFORM_MACOS)
    target_link_libraries(osquery_tables_system PUBLIC
      thirdparty_openssl
    )
  endif()

  set(public_header_files
    efi_misc.h
    intel_me.hpp
    smbios_utils.h
    system_utils.h
    user_groups.h
  )

  generateIncludeNamespace(osquery_tables_system "osquery/tables/system" "FILE_ONLY" ${public_header_files})

  if(DEFINED PLATFORM_POSIX)
    set(platform_public_header_files
      posix/known_hosts.h
      posix/shell_history.h
      posix/sysctl_utils.h
    )
  endif()

  if(DEFINED PLATFORM_LINUX)
    list(APPEND platform_public_header_files
      linux/md_tables.h
      linux/pci_devices.h
      linux/smbios_utils.h
    )

  elseif(DEFINED PLATFORM_MACOS)
    list(APPEND platform_public_header_files
      darwin/asl_utils.h
      darwin/firewall.h
      darwin/keychain.h
      darwin/packages.h
      darwin/smbios_utils.h
    )

  elseif(DEFINED PLATFORM_FREEBSD)
    list(APPEND platform_public_header_files
      freebsd/procstat.h
    )

  elseif(DEFINED PLATFORM_WINDOWS)
    list(APPEND platform_public_header_files
      windows/registry.h
    )
  endif()

  generateIncludeNamespace(osquery_tables_system "osquery/tables/system" "FULL_PATH" ${platform_public_header_files})
endfunction()

osquery_tables_system_main()

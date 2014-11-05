
/** @jsx React.DOM */

'use strict';

var API = [


  {name: "All Platforms", tables: [

    {name: "bash_history", columns: [
      {name: "username", type: "std::string", description: "", tables: ""}, 
      {name: "command", type: "std::string", description: "", tables: ""}, 
      {name: "history_file", type: "std::string", description: "", tables: ""}
    ]}, 

    {name: "cpuid", columns: [
      {name: "feature", type: "std::string", description: "", tables: ""}, 
      {name: "value", type: "std::string", description: "", tables: ""}, 
      {name: "output_register", type: "std::string", description: "", tables: ""}, 
      {name: "output_bit", type: "std::string", description: "", tables: ""}, 
      {name: "input_eax", type: "std::string", description: "", tables: ""}
    ]}, 

    {name: "crontab", columns: [
      {name: "event", type: "std::string", description: "", tables: ""}, 
      {name: "minute", type: "std::string", description: "", tables: ""}, 
      {name: "hour", type: "std::string", description: "", tables: ""}, 
      {name: "day_of_month", type: "std::string", description: "", tables: ""}, 
      {name: "month", type: "std::string", description: "", tables: ""}, 
      {name: "day_of_week", type: "std::string", description: "", tables: ""}, 
      {name: "command", type: "std::string", description: "", tables: ""}, 
      {name: "path", type: "std::string", description: "", tables: ""}
    ]}, 

    {name: "etc_hosts", columns: [
      {name: "address", type: "std::string", description: "", tables: ""}, 
      {name: "hostnames", type: "std::string", description: "", tables: ""}
    ]}, 

    {name: "groups", columns: [
      {name: "gid", type: "long long int", description: "", tables: ""}, 
      {name: "name", type: "std::string", description: "", tables: ""}
    ]}, 

    {name: "last", columns: [
      {name: "login", type: "std::string", description: "", tables: ""}, 
      {name: "tty", type: "std::string", description: "", tables: ""}, 
      {name: "pid", type: "int", description: "", tables: ""}, 
      {name: "type", type: "int", description: "", tables: ""}, 
      {name: "time", type: "int", description: "", tables: ""}, 
      {name: "host", type: "std::string", description: "", tables: ""}
    ]}, 

    {name: "passwd_changes", columns: [
      {name: "target_path", type: "std::string", description: "", tables: ""}, 
      {name: "time", type: "std::string", description: "", tables: ""}, 
      {name: "action", type: "std::string", description: "", tables: ""}, 
      {name: "transaction_id", type: "std::string", description: "", tables: ""}
    ]}, 

    {name: "process_envs", columns: [
      {name: "pid", type: "int", description: "", tables: ""}, 
      {name: "name", type: "std::string", description: "", tables: ""}, 
      {name: "path", type: "std::string", description: "", tables: ""}, 
      {name: "key", type: "std::string", description: "", tables: ""}, 
      {name: "value", type: "std::string", description: "", tables: ""}
    ]}, 

    {name: "process_open_files", columns: [
      {name: "pid", type: "int", description: "", tables: ""}, 
      {name: "name", type: "std::string", description: "", tables: ""}, 
      {name: "path", type: "std::string", description: "", tables: ""}, 
      {name: "file_type", type: "std::string", description: "", tables: ""}, 
      {name: "local_path", type: "std::string", description: "", tables: ""}, 
      {name: "local_host", type: "std::string", description: "", tables: ""}, 
      {name: "local_port", type: "std::string", description: "", tables: ""}, 
      {name: "remote_host", type: "std::string", description: "", tables: ""}, 
      {name: "remote_port", type: "std::string", description: "", tables: ""}
    ]}, 

    {name: "processes", columns: [
      {name: "name", type: "std::string", description: "", tables: ""}, 
      {name: "path", type: "std::string", description: "", tables: ""}, 
      {name: "cmdline", type: "std::string", description: "", tables: ""}, 
      {name: "pid", type: "int", description: "", tables: ""}, 
      {name: "on_disk", type: "std::string", description: "", tables: ""}, 
      {name: "wired_size", type: "std::string", description: "", tables: ""}, 
      {name: "resident_size", type: "std::string", description: "", tables: ""}, 
      {name: "phys_footprint", type: "std::string", description: "", tables: ""}, 
      {name: "user_time", type: "std::string", description: "", tables: ""}, 
      {name: "system_time", type: "std::string", description: "", tables: ""}, 
      {name: "start_time", type: "std::string", description: "", tables: ""}, 
      {name: "parent", type: "int", description: "", tables: ""}
    ]}, 

    {name: "routes", columns: [
      {name: "destination", type: "std::string", description: "", tables: ""}, 
      {name: "netmask", type: "std::string", description: "", tables: ""}, 
      {name: "gateway", type: "std::string", description: "", tables: ""}, 
      {name: "source", type: "std::string", description: "", tables: ""}, 
      {name: "flags", type: "int", description: "", tables: ""}, 
      {name: "interface", type: "std::string", description: "", tables: ""}, 
      {name: "mtu", type: "int", description: "", tables: ""}, 
      {name: "metric", type: "int", description: "", tables: ""}, 
      {name: "type", type: "std::string", description: "", tables: ""}
    ]}, 

    {name: "suid_bin", columns: [
      {name: "path", type: "std::string", description: "", tables: ""}, 
      {name: "unix_user", type: "std::string", description: "", tables: ""}, 
      {name: "unix_group", type: "std::string", description: "", tables: ""}, 
      {name: "permissions", type: "std::string", description: "", tables: ""}
    ]}, 

    {name: "time", columns: [
      {name: "hour", type: "int", description: "", tables: ""}, 
      {name: "minutes", type: "int", description: "", tables: ""}, 
      {name: "seconds", type: "int", description: "", tables: ""}
    ]}, 

    {name: "users", columns: [
      {name: "uid", type: "long long int", description: "", tables: ""}, 
      {name: "gid", type: "long long int", description: "", tables: ""}, 
      {name: "username", type: "std::string", description: "", tables: ""}, 
      {name: "description", type: "std::string", description: "", tables: ""}, 
      {name: "directory", type: "std::string", description: "", tables: ""}, 
      {name: "shell", type: "std::string", description: "", tables: ""}
    ]}
  ]}, 

  {name: "Darwin (Apple OS X)", tables: [

    {name: "alf", columns: [
      {name: "allow_signed_enabled", type: "int", description: "", tables: ""}, 
      {name: "firewall_unload", type: "int", description: "", tables: ""}, 
      {name: "global_state", type: "int", description: "", tables: ""}, 
      {name: "logging_enabled", type: "int", description: "", tables: ""}, 
      {name: "logging_option", type: "int", description: "", tables: ""}, 
      {name: "stealth_enabled", type: "int", description: "", tables: ""}, 
      {name: "version", type: "std::string", description: "", tables: ""}
    ]}, 

    {name: "alf_exceptions", columns: [
      {name: "path", type: "std::string", description: "", tables: ""}, 
      {name: "state", type: "int", description: "", tables: ""}
    ]}, 

    {name: "alf_explicit_auths", columns: [
      {name: "process", type: "std::string", description: "", tables: ""}
    ]}, 

    {name: "alf_services", columns: [
      {name: "service", type: "std::string", description: "", tables: ""}, 
      {name: "process", type: "std::string", description: "", tables: ""}, 
      {name: "state", type: "int", description: "", tables: ""}
    ]}, 

    {name: "apps", columns: [
      {name: "name", type: "std::string", description: "", tables: ""}, 
      {name: "path", type: "std::string", description: "", tables: ""}, 
      {name: "bundle_executable", type: "std::string", description: "", tables: ""}, 
      {name: "bundle_identifier", type: "std::string", description: "", tables: ""}, 
      {name: "bundle_name", type: "std::string", description: "", tables: ""}, 
      {name: "bundle_short_version", type: "std::string", description: "", tables: ""}, 
      {name: "bundle_version", type: "std::string", description: "", tables: ""}, 
      {name: "bundle_package_type", type: "std::string", description: "", tables: ""}, 
      {name: "compiler", type: "std::string", description: "", tables: ""}, 
      {name: "development_region", type: "std::string", description: "", tables: ""}, 
      {name: "display_name", type: "std::string", description: "", tables: ""}, 
      {name: "info_string", type: "std::string", description: "", tables: ""}, 
      {name: "minimum_system_version", type: "std::string", description: "", tables: ""}, 
      {name: "category", type: "std::string", description: "", tables: ""}, 
      {name: "applescript_enabled", type: "std::string", description: "", tables: ""}, 
      {name: "copyright", type: "std::string", description: "", tables: ""}
    ]}, 

    {name: "ca_certs", columns: [
      {name: "common_name", type: "std::string", description: "", tables: ""}, 
      {name: "not_valid_before", type: "std::string", description: "", tables: ""}, 
      {name: "not_valid_after", type: "std::string", description: "", tables: ""}, 
      {name: "key_algorithm", type: "std::string", description: "", tables: ""}, 
      {name: "key_usage", type: "std::string", description: "", tables: ""}, 
      {name: "subject_key_id", type: "std::string", description: "", tables: ""}, 
      {name: "authority_key_id", type: "std::string", description: "", tables: ""}, 
      {name: "sha1", type: "std::string", description: "", tables: ""}
    ]}, 

    {name: "homebrew_packages", columns: [
      {name: "name", type: "std::string", description: "", tables: ""}, 
      {name: "path", type: "std::string", description: "", tables: ""}, 
      {name: "version", type: "std::string", description: "", tables: ""}
    ]}, 

    {name: "interface_addresses", columns: [
      {name: "interface", type: "std::string", description: "", tables: ""}, 
      {name: "address", type: "std::string", description: "", tables: ""}, 
      {name: "mask", type: "std::string", description: "", tables: ""}, 
      {name: "broadcast", type: "std::string", description: "", tables: ""}, 
      {name: "point_to_point", type: "std::string", description: "", tables: ""}
    ]}, 

    {name: "interface_details", columns: [
      {name: "interface", type: "std::string", description: "", tables: ""}, 
      {name: "mac", type: "std::string", description: "", tables: ""}, 
      {name: "type", type: "int", description: "", tables: ""}, 
      {name: "mtu", type: "std::string", description: "", tables: ""}, 
      {name: "metric", type: "std::string", description: "", tables: ""}, 
      {name: "ipackets", type: "std::string", description: "", tables: ""}, 
      {name: "opackets", type: "std::string", description: "", tables: ""}, 
      {name: "ibytes", type: "std::string", description: "", tables: ""}, 
      {name: "obytes", type: "std::string", description: "", tables: ""}, 
      {name: "ierrors", type: "std::string", description: "", tables: ""}, 
      {name: "oerrors", type: "std::string", description: "", tables: ""}, 
      {name: "last_change", type: "std::string", description: "", tables: ""}
    ]}, 

    {name: "kextstat", columns: [
      {name: "idx", type: "int", description: "", tables: ""}, 
      {name: "refs", type: "int", description: "", tables: ""}, 
      {name: "size", type: "std::string", description: "", tables: ""}, 
      {name: "wired", type: "std::string", description: "", tables: ""}, 
      {name: "name", type: "std::string", description: "", tables: ""}, 
      {name: "version", type: "std::string", description: "", tables: ""}, 
      {name: "linked_against", type: "std::string", description: "", tables: ""}
    ]}, 

    {name: "launchd", columns: [
      {name: "path", type: "std::string", description: "", tables: ""}, 
      {name: "name", type: "std::string", description: "", tables: ""}, 
      {name: "label", type: "std::string", description: "", tables: ""}, 
      {name: "run_at_load", type: "std::string", description: "", tables: ""}, 
      {name: "keep_alive", type: "std::string", description: "", tables: ""}, 
      {name: "on_demand", type: "std::string", description: "", tables: ""}, 
      {name: "disabled", type: "std::string", description: "", tables: ""}, 
      {name: "user_name", type: "std::string", description: "", tables: ""}, 
      {name: "group_name", type: "std::string", description: "", tables: ""}, 
      {name: "stdout_path", type: "std::string", description: "", tables: ""}, 
      {name: "stderr_path", type: "std::string", description: "", tables: ""}, 
      {name: "start_interval", type: "std::string", description: "", tables: ""}, 
      {name: "program_arguments", type: "std::string", description: "", tables: ""}, 
      {name: "program", type: "std::string", description: "", tables: ""}, 
      {name: "watch_paths", type: "std::string", description: "", tables: ""}, 
      {name: "queue_directories", type: "std::string", description: "", tables: ""}, 
      {name: "inetd_compatibility", type: "std::string", description: "", tables: ""}, 
      {name: "start_on_mount", type: "std::string", description: "", tables: ""}, 
      {name: "root_directory", type: "std::string", description: "", tables: ""}, 
      {name: "working_directory", type: "std::string", description: "", tables: ""}, 
      {name: "process_type", type: "std::string", description: "", tables: ""}
    ]}, 

    {name: "listening_ports", columns: [
      {name: "pid", type: "int", description: "", tables: ""}, 
      {name: "port", type: "int", description: "", tables: ""}, 
      {name: "protocol", type: "int", description: "", tables: ""}, 
      {name: "family", type: "int", description: "", tables: ""}, 
      {name: "address", type: "std::string", description: "", tables: ""}
    ]}, 

    {name: "nvram", columns: [
      {name: "name", type: "std::string", description: "", tables: ""}, 
      {name: "type", type: "std::string", description: "", tables: ""}, 
      {name: "value", type: "std::string", description: "", tables: ""}
    ]}, 

    {name: "osx_version", columns: [
      {name: "major", type: "int", description: "", tables: ""}, 
      {name: "minor", type: "int", description: "", tables: ""}, 
      {name: "patch", type: "int", description: "", tables: ""}
    ]}, 

    {name: "quarantine", columns: [
      {name: "path", type: "std::string", description: "", tables: ""}, 
      {name: "creator", type: "std::string", description: "", tables: ""}
    ]}
  ]}, 

  {name: "Ubuntu, CentOS", tables: [

    {name: "block_devices", columns: [
      {name: "name", type: "std::string", description: "", tables: ""}, 
      {name: "parent", type: "std::string", description: "", tables: ""}, 
      {name: "vendor", type: "std::string", description: "", tables: ""}, 
      {name: "model", type: "std::string", description: "", tables: ""}, 
      {name: "size", type: "long long int", description: "", tables: ""}, 
      {name: "uuid", type: "std::string", description: "", tables: ""}, 
      {name: "type", type: "std::string", description: "", tables: ""}, 
      {name: "label", type: "std::string", description: "", tables: ""}
    ]}, 

    {name: "kernel_modules", columns: [
      {name: "name", type: "std::string", description: "", tables: ""}, 
      {name: "size", type: "std::string", description: "", tables: ""}, 
      {name: "used_by", type: "std::string", description: "", tables: ""}, 
      {name: "status", type: "std::string", description: "", tables: ""}, 
      {name: "address", type: "std::string", description: "", tables: ""}
    ]}, 

    {name: "mounts", columns: [
      {name: "fsname", type: "std::string", description: "", tables: ""}, 
      {name: "fsname_real", type: "std::string", description: "", tables: ""}, 
      {name: "path", type: "std::string", description: "", tables: ""}, 
      {name: "type", type: "std::string", description: "", tables: ""}, 
      {name: "opts", type: "std::string", description: "", tables: ""}, 
      {name: "freq", type: "int", description: "", tables: ""}, 
      {name: "passno", type: "int", description: "", tables: ""}, 
      {name: "block_size", type: "long long int", description: "", tables: ""}, 
      {name: "blocks", type: "long long int", description: "", tables: ""}, 
      {name: "blocks_free", type: "long long int", description: "", tables: ""}, 
      {name: "blocks_avail", type: "long long int", description: "", tables: ""}, 
      {name: "inodes", type: "long long int", description: "", tables: ""}, 
      {name: "inodes_free", type: "long long int", description: "", tables: ""}
    ]}, 

    {name: "pci_devices", columns: [
      {name: "slot", type: "std::string", description: "", tables: ""}, 
      {name: "device_class", type: "std::string", description: "", tables: ""}, 
      {name: "vendor", type: "std::string", description: "", tables: ""}, 
      {name: "model", type: "std::string", description: "", tables: ""}
    ]}, 

    {name: "rpm_packages", columns: [
      {name: "name", type: "std::string", description: "", tables: ""}, 
      {name: "version", type: "std::string", description: "", tables: ""}, 
      {name: "release", type: "std::string", description: "", tables: ""}, 
      {name: "source", type: "std::string", description: "", tables: ""}, 
      {name: "size", type: "std::string", description: "", tables: ""}, 
      {name: "dsaheader", type: "std::string", description: "", tables: ""}, 
      {name: "rsaheader", type: "std::string", description: "", tables: ""}, 
      {name: "sha1header", type: "std::string", description: "", tables: ""}, 
      {name: "arch", type: "std::string", description: "", tables: ""}
    ]}
  ]}
];

module.exports = API;



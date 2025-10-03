#!/bin/bash
# EndpointSecurity Cross-Version Testing Script
# Tests EndpointSecurity functionality across different macOS versions

set -e

# Detect macOS version
MACOS_VERSION=$(sw_vers -productVersion | cut -d. -f1)
echo "Detected macOS version: $MACOS_VERSION"

# Output directory for test results
RESULTS_DIR="es_test_results"
mkdir -p "$RESULTS_DIR"

# Configure environment based on macOS version
configure_test_env() {
  echo "Configuring test environment for macOS $MACOS_VERSION..."
  
  # Sign with entitlements if the file exists
  if [ -f "es_entitlements.xml" ]; then
    echo "Signing binary with entitlements..."
    codesign --force --sign - --entitlements es_entitlements.xml ./build/osqueryi
    
    # Verify entitlements were applied
    echo "Verifying entitlements..."
    codesign -d --entitlements - ./build/osqueryi | grep -q "com.apple.developer.endpoint-security.client" || echo "WARNING: EndpointSecurity entitlement not found!"
  else
    echo "WARNING: es_entitlements.xml not found, skipping signing"
  fi
  
  # Base flags for all versions
  BASE_FLAGS="--disable_events=false --disable_endpointsecurity=false --events_expiry=1"
  
  # Version-specific flags
  if [ "$MACOS_VERSION" -ge 11 ]; then
    BASE_FLAGS="$BASE_FLAGS --enable_es_memory_events=true"
  fi
  
  if [ "$MACOS_VERSION" -ge 12 ]; then
    BASE_FLAGS="$BASE_FLAGS --enable_es_system_events=true"
  fi
  
  if [ "$MACOS_VERSION" -ge 13 ]; then
    BASE_FLAGS="$BASE_FLAGS --enable_es_authentication_events=true"
  fi
  
  if [ "$MACOS_VERSION" -ge 14 ]; then
    BASE_FLAGS="$BASE_FLAGS --enable_es_xpc_events=true"
  fi
  
  echo "Using flags: $BASE_FLAGS"
  export BASE_FLAGS
  return 0
}

# Helper function to run a test and log results
run_test() {
  local test_name="$1"
  local query="$2"
  local expected_output="$3"
  local min_version="$4"
  
  # Check if this test should run on current macOS version
  if [ -n "$min_version" ] && [ "$MACOS_VERSION" -lt "$min_version" ]; then
    echo "SKIPPED: $test_name (requires macOS $min_version+)"
    echo "TEST: $test_name - SKIPPED (requires macOS $min_version+)" >> "$RESULTS_DIR/summary.log"
    return 0
  fi
  
  echo "Running test: $test_name"
  echo "Query: $query"
  
  # Run the test with timeout
  local result
  result=$(timeout 10s ./build/osqueryi $BASE_FLAGS --config_path=/dev/null --logger_path=stdout "$query" 2>&1)
  local status=$?
  
  # Save full output
  echo "$result" > "$RESULTS_DIR/${test_name}.log"
  
  # Check results
  if [ $status -ne 0 ]; then
    echo "FAILED: $test_name (exit code $status)"
    echo "TEST: $test_name - FAILED (exit code $status)" >> "$RESULTS_DIR/summary.log"
    return 1
  fi
  
  # If expected output is provided, check for it
  if [ -n "$expected_output" ]; then
    if echo "$result" | grep -q "$expected_output"; then
      echo "PASSED: $test_name"
      echo "TEST: $test_name - PASSED" >> "$RESULTS_DIR/summary.log"
      return 0
    else
      echo "FAILED: $test_name (expected output not found)"
      echo "TEST: $test_name - FAILED (expected output not found)" >> "$RESULTS_DIR/summary.log"
      return 1
    fi
  else
    # Just check that we got some output
    if [ -n "$result" ]; then
      echo "PASSED: $test_name"
      echo "TEST: $test_name - PASSED" >> "$RESULTS_DIR/summary.log"
      return 0
    else
      echo "FAILED: $test_name (no output)"
      echo "TEST: $test_name - FAILED (no output)" >> "$RESULTS_DIR/summary.log"
      return 1
    fi
  fi
}

# Run base tests for all versions (macOS 10.15+)
run_base_tests() {
  echo "Running base tests for macOS $MACOS_VERSION..."
  
  # Check that the tables exist
  run_test "es_process_events_table_exists" \
    "SELECT name FROM sqlite_master WHERE type='table' AND name='es_process_events';" \
    "es_process_events"
    
  run_test "es_security_events_table_exists" \
    "SELECT name FROM sqlite_master WHERE type='table' AND name='es_security_events';" \
    "es_security_events"
    
  # Test basic process events
  run_test "basic_process_events" \
    "SELECT event_type FROM es_process_events LIMIT 1;" \
    "exec"
    
  # Test file events (available on all versions)
  run_test "basic_file_events" \
    "SELECT * FROM es_security_events WHERE category='file_system' LIMIT 1;" \
    ""
}

# Run macOS 11+ tests (Big Sur)
run_bigsur_tests() {
  if [ "$MACOS_VERSION" -lt 11 ]; then
    echo "Skipping macOS 11+ tests (current version: $MACOS_VERSION)"
    return 0
  fi
  
  echo "Running macOS 11+ tests..."
  
  # Test memory protection events
  run_test "memory_protection_events" \
    "SELECT * FROM es_security_events WHERE event_type IN ('mmap', 'mprotect') LIMIT 1;" \
    "" \
    11
}

# Run macOS 12+ tests (Monterey)
run_monterey_tests() {
  if [ "$MACOS_VERSION" -lt 12 ]; then
    echo "Skipping macOS 12+ tests (current version: $MACOS_VERSION)"
    return 0
  fi
  
  echo "Running macOS 12+ tests..."
  
  # Test UID/GID operations
  run_test "uid_gid_operations" \
    "SELECT * FROM es_security_events WHERE event_type IN ('setuid', 'seteuid', 'setreuid', 'setegid', 'setregid') LIMIT 1;" \
    "" \
    12
}

# Run macOS 13+ tests (Ventura)
run_ventura_tests() {
  if [ "$MACOS_VERSION" -lt 13 ]; then
    echo "Skipping macOS 13+ tests (current version: $MACOS_VERSION)"
    return 0
  fi
  
  echo "Running macOS 13+ tests..."
  
  # Test authentication events
  run_test "authentication_events" \
    "SELECT * FROM es_security_events WHERE category='authentication' LIMIT 1;" \
    "" \
    13
    
  # Test SSH events
  run_test "ssh_events" \
    "SELECT * FROM es_security_events WHERE event_type IN ('openssh_login', 'openssh_logout') LIMIT 1;" \
    "" \
    13
}

# Run macOS 14+ tests (Sonoma)
run_sonoma_tests() {
  if [ "$MACOS_VERSION" -lt 14 ]; then
    echo "Skipping macOS 14+ tests (current version: $MACOS_VERSION)"
    return 0
  fi
  
  echo "Running macOS 14+ tests..."
  
  # Test XPC events
  run_test "xpc_events" \
    "SELECT * FROM es_security_events WHERE event_type LIKE 'xpc%' LIMIT 1;" \
    "" \
    14
    
  # Test SU/SUDO events
  run_test "su_sudo_events" \
    "SELECT * FROM es_security_events WHERE event_type IN ('su', 'sudo') LIMIT 1;" \
    "" \
    14
}

# Test event categorization
test_event_categorization() {
  echo "Testing event categorization..."
  
  # Check process event category
  run_test "process_event_category" \
    "SELECT DISTINCT category FROM es_security_events WHERE event_type IN ('exec', 'fork', 'exit') LIMIT 1;" \
    "process"
    
  # Check file system event category
  run_test "file_event_category" \
    "SELECT DISTINCT category FROM es_security_events WHERE event_type IN ('create', 'open', 'close', 'rename', 'write') LIMIT 1;" \
    "file_system"
}

# Test severity classification
test_severity_classification() {
  echo "Testing severity classification..."
  
  # Check high severity events
  run_test "high_severity_events" \
    "SELECT COUNT(*) FROM es_security_events WHERE severity='high';" \
    ""
    
  # Check medium severity events
  run_test "medium_severity_events" \
    "SELECT COUNT(*) FROM es_security_events WHERE severity='medium';" \
    ""
    
  # Check low severity events
  run_test "low_severity_events" \
    "SELECT COUNT(*) FROM es_security_events WHERE severity='low';" \
    ""
}

# Test version-specific features
test_version_features() {
  echo "Testing version-specific feature detection..."
  
  # Test feature availability with process events (available on all versions)
  run_test "process_events_available" \
    "SELECT name, description FROM osquery_events WHERE publisher='endpointsecurity' AND name LIKE '%process%';" \
    "process"
    
  # Test memory events availability (macOS 11+)
  run_test "memory_events_availability" \
    "SELECT name, description FROM osquery_events WHERE publisher='endpointsecurity' AND name LIKE '%memory%';" \
    "" \
    11
    
  # Test auth events availability (macOS 13+)
  run_test "auth_events_availability" \
    "SELECT name, description FROM osquery_events WHERE publisher='endpointsecurity' AND name LIKE '%auth%';" \
    "" \
    13
}

# Run all tests and summarize results
run_all_tests() {
  echo "Starting EndpointSecurity test suite for macOS $MACOS_VERSION..."
  echo "Test started at $(date)" > "$RESULTS_DIR/summary.log"
  echo "macOS version: $MACOS_VERSION" >> "$RESULTS_DIR/summary.log"
  
  # Run all test groups
  run_base_tests
  run_bigsur_tests
  run_monterey_tests
  run_ventura_tests
  run_sonoma_tests
  test_event_categorization
  test_severity_classification
  test_version_features
  
  # Also run the C++ unit tests
  echo "Running C++ unit tests..."
  cd build
  ctest -L endpointsecurity -V
  cd ..
  
  # Summarize results
  echo "---------------------------------------"
  echo "EndpointSecurity Test Suite Summary:"
  echo "---------------------------------------"
  echo "Tests completed at $(date)" >> "$RESULTS_DIR/summary.log"
  
  # Count passed/failed/skipped tests
  passed=$(grep -c "PASSED" "$RESULTS_DIR/summary.log" || true)
  failed=$(grep -c "FAILED" "$RESULTS_DIR/summary.log" || true)
  skipped=$(grep -c "SKIPPED" "$RESULTS_DIR/summary.log" || true)
  total=$((passed + failed + skipped))
  
  echo "Total tests:  $total"
  echo "Passed:       $passed"
  echo "Failed:       $failed"
  echo "Skipped:      $skipped"
  
  echo "---------------------------------------"
  echo "Total tests:  $total" >> "$RESULTS_DIR/summary.log"
  echo "Passed:       $passed" >> "$RESULTS_DIR/summary.log"
  echo "Failed:       $failed" >> "$RESULTS_DIR/summary.log"
  echo "Skipped:      $skipped" >> "$RESULTS_DIR/summary.log"
  
  # Exit with failure if any tests failed
  if [ $failed -gt 0 ]; then
    echo "Test suite FAILED"
    echo "Test suite FAILED" >> "$RESULTS_DIR/summary.log"
    return 1
  else
    echo "Test suite PASSED"
    echo "Test suite PASSED" >> "$RESULTS_DIR/summary.log"
    return 0
  fi
}

# Main execution
configure_test_env
run_all_tests
exit $?
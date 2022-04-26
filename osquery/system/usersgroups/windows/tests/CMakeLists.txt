function(osquerySystemUsersGroupsWindowsTestsMain)
    generateOsquerySystemUsersGroupsWindowsTestsUsersgroupscachetest()
endfunction()

function(generateOsquerySystemUsersGroupsWindowsTestsUsersgroupscachetest)
    add_osquery_executable(osquery_system_usersgroups_tests_cache-test
        users_groups_cache.cpp
    )

    target_link_libraries(osquery_system_usersgroups_tests_cache-test PRIVATE
        osquery_cxx_settings
        osquery_system_usersgroups_caches
        thirdparty_googletest
    )

    add_test(NAME osquery_system_usersgroups_tests_cache-test COMMAND osquery_system_usersgroups_tests_cache-test)
endfunction()

osquerySystemUsersGroupsWindowsTestsMain()

// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

namespace osquery {

// Run a shell with all of the relevant virtual tables loaded
/** @brief Run an interactive SQL query shell.
 *
 *  @code{.cpp}
 *    // Copyright 2004-present Facebook. All Rights Reserved.
 *    #include "osquery/core.h"
 *    #include "osquery/devtools.h"

 *    int main(int argc, char *argv[]) {
 *      osquery::initOsquery(argc, argv);
 *      return osquery::launchIntoShell(argc, argv);
 *    }
 *  @endcode
 *
 *  @param argc the number of elements in argv
 *  @param argv the command-line flags
 *
 *  @return an int which represents the "return code"
 */
int launchIntoShell(int argc, char **argv);
}

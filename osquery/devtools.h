// Copyright 2004-present Facebook. All Rights Reserved.

#ifndef OSQUERY_DEVTOOLS_H
#define OSQUERY_DEVTOOLS_H

namespace osquery { namespace devtools {

// Run a shell with all of the relevant virtual tables loaded
int launchIntoShell(int argc, char **argv);

}}

#endif /* OSQUERY_DEVTOOLS_H */

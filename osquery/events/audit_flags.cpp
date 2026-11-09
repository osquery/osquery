/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/flags.h>

namespace osquery {

/**
 * The Auditd/OpenBSM subsystem may have a performance impact on the system.
 *
 * This flag controls Auditd on Linux and OpenBSM on macOS.
 */
FLAG(bool,
     disable_audit,
     true,
     "Disable receiving events from the audit subsystem");

/// Control the audit subsystem by allowing subscriptions to apply rules.
FLAG(bool,
     audit_allow_config,
     false,
     "Allow the audit publisher to change auditing configuration");

FLAG(bool,
     audit_allow_sockets,
     false,
     "Allow the audit publisher to install socket-related rules");

FLAG(bool,
     audit_allow_process_events,
     true,
     "Allow the audit publisher to install process-related rules");

FLAG(bool,
     audit_allow_user_events,
     true,
     "Allow the audit publisher to install user-related rules");

FLAG(bool,
     audit_allow_fim_events,
     false,
     "Allow the audit publisher to install filesystem-related rules");

#ifdef OSQUERY_LINUX
// The Linux audit publishers use these, so they are defined with the events
// library rather than with the event tables that depend on it.

FLAG(bool,
     audit_allow_fork_process_events,
     false,
     "Allow the audit publisher to install process event monitoring rules to "
     "capture fork/vfork/clone system calls");

FLAG(bool,
     audit_allow_kill_process_events,
     false,
     "Allow the audit publisher to install process event monitoring rules to "
     "capture kill/tkill/tgkill system calls");

FLAG(bool,
     audit_allow_apparmor_events,
     false,
     "Allow the publisher to process audit events");

FLAG(bool,
     audit_allow_seccomp_events,
     false,
     "Allow the audit publisher to process seccomp events");

FLAG(bool,
     audit_allow_selinux_events,
     false,
     "Allow the audit publisher to process audit events");
#endif

} // namespace osquery

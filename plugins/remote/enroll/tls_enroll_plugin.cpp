/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/registry_factory.h>
#include <osquery/remote/enroll/tls_enroll.h>

namespace osquery {

REGISTER(TLSEnrollPlugin, "enroll", "tls");

}

/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <osquery/extensions/interface.h>

#include "Extension.h"
#include "ExtensionManager.h"

namespace osquery {

class ExtensionHandler : virtual public extensions::ExtensionIf,
                         public ExtensionInterface {
 public:
  ExtensionHandler() : ExtensionInterface(0) {}
  explicit ExtensionHandler(RouteUUID uuid) : ExtensionInterface(uuid) {}

 public:
  using ExtensionInterface::ping;
  void ping(extensions::ExtensionStatus& _return) override;

  using ExtensionInterface::call;
  void call(extensions::ExtensionResponse& _return,
            const std::string& registry,
            const std::string& item,
            const extensions::ExtensionPluginRequest& request) override;

  using ExtensionInterface::shutdown;
  void shutdown() override;

 protected:
  /// UUID accessor.
  RouteUUID getUUID() const;
};

#ifdef WIN32
#pragma warning(push, 3)
#pragma warning(disable : 4250)
#endif

class ExtensionManagerHandler : virtual public extensions::ExtensionManagerIf,
                                public ExtensionManagerInterface,
                                public ExtensionHandler {
 public:
  ExtensionManagerHandler() = default;

 public:
  using ExtensionManagerInterface::extensions;
  void extensions(extensions::InternalExtensionList& _return) override;

  using ExtensionManagerInterface::options;
  void options(extensions::InternalOptionList& _return) override;

  using ExtensionManagerInterface::registerExtension;
  void registerExtension(
      extensions::ExtensionStatus& _return,
      const extensions::InternalExtensionInfo& info,
      const extensions::ExtensionRegistry& registry) override;

  using ExtensionManagerInterface::deregisterExtension;
  void deregisterExtension(extensions::ExtensionStatus& _return,
                           const extensions::ExtensionRouteUUID uuid) override;

  using ExtensionManagerInterface::query;
  void query(extensions::ExtensionResponse& _return,
             const std::string& sql) override;

  using ExtensionManagerInterface::getQueryColumns;
  void getQueryColumns(extensions::ExtensionResponse& _return,
                       const std::string& sql) override;

 public:
  using ExtensionHandler::call;
  using ExtensionHandler::ping;
  using ExtensionHandler::shutdown;
};

#ifdef WIN32
#pragma warning(pop)
#endif

} // namespace osquery

// Copyright 2004-present Facebook. All Rights Reserved.

#ifndef OSQUERY_REGISTRY_H
#define OSQUERY_REGISTRY_H

#include <functional>
#include <string>
#include <unordered_map>
#include <utility>

#include <glog/logging.h>

#include "osquery/registry/init_registry.h"
#include "osquery/registry/singleton.h"

namespace osquery {

/**
 * A simple registry system for making values available by key across
 * components.
 *
 * To use this registry, make a header like so:
 *
 *   #include "osquery/registry/registry.h"
 *
 *   DECLARE_REGISTRY(MathFuncs, int, std::function<double(double)>)
 *   #define REGISTERED_MATH_FUNCS REGISTRY(MathFuncs)
 *   #define REGISTER_MATH_FUNC(id, func) \
 *           REGISTER(MathFuncs, id, func)
 *
 * Client code may then advertise an entry from a .cpp like so:
 *   #include "my/registry/header.h"
 *
 *   REGISTER_MATH_FUNC(1, sqrt);
 *
 * Server code may then access the set of registered values by using
 * REGISTERED_MATH_FUNCS as a map, which will be populated after
 * osquery::InitRegistry::get().run() has been called.
 */
template <class Key, class Value>
class Registry : public std::unordered_map<Key, Value> {
public:
  void registerValue(const Key &key, const Value &value,
                     const char *displayName = "registry") {
    if (this->insert(std::make_pair(key, value)).second) {
      VLOG(1) << displayName << "[" << key << "]"
              << " registered";
    } else {
      LOG(ERROR) << displayName << "[" << key << "]"
                 << " already registered";
    }
  }
};
}

#define DECLARE_REGISTRY(registryName, KeyType, ObjectType)                    \
  namespace osquery {                                                          \
  namespace registries {                                                       \
  class registryName : public Registry<KeyType, ObjectType> {};                \
  }                                                                            \
  } // osquery::registries

#define REGISTRY(registryName)                                                 \
  (osquery::Singleton<osquery::registries::registryName>::get())

#ifndef UNIQUE_VAR
#define UNIQUE_VAR_CONCAT(_name_, _line_) _name_##_line_
#define UNIQUE_VAR_LINENAME(_name_, _line_) UNIQUE_VAR_CONCAT(_name_, _line_)
#define UNIQUE_VAR(_name_) UNIQUE_VAR_LINENAME(_name_, __LINE__)
#endif

#define REGISTER(registryName, key, value)                                     \
  namespace { /* require global scope, don't pollute static namespace */       \
  static osquery::RegisterInitFunc UNIQUE_VAR(registryName)([] {               \
    REGISTRY(registryName).registerValue((key), (value), #registryName);       \
  });                                                                          \
  }

#endif /* OSQUERY_REGISTRY_H */

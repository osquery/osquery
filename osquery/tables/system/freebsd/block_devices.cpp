/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 *
 * FreeBSD block_devices: walk the GEOM tree via libgeom (base) and emit one
 * row per provider.  Each provider's class (DISK, PART, LABEL, …) maps to
 * the table's "type" column.  Parent is the consumer's provider (i.e. the
 * disk that a partition lives on); UUID/label are pulled from gpart config
 * (rawuuid/label) and from LABEL-class providers whose consumer points at
 * the partition.
 */

#include <libgeom.h>
#include <sys/types.h>

#include <map>
#include <string>

#include <osquery/core/tables.h>
#include <osquery/registry/registry_factory.h>

namespace osquery {
namespace tables {

static std::string gconfigGet(const struct gconf* cfg, const char* key) {
  struct gconfig* c;
  LIST_FOREACH(c, cfg, lg_config) {
    if (c->lg_name != nullptr && std::string(c->lg_name) == key) {
      return c->lg_val != nullptr ? std::string(c->lg_val) : "";
    }
  }
  return "";
}

QueryData genBlockDevs(QueryContext& context) {
  QueryData results;
  struct gmesh mesh;
  if (geom_gettree(&mesh) != 0) {
    return results;
  }

  // Pre-pass: build a map from provider id → name, used to resolve a geom's
  // "parent" via its consumer's provider.
  std::map<void*, std::string> provider_names;
  // And a reverse map: for each provider name, look up labels attached to it
  // via the LABEL class (so partitions get their filesystem labels).
  std::map<std::string, std::string> labels_for;
  std::map<std::string, std::string> uuids_for;

  struct gclass* cls;
  LIST_FOREACH(cls, &mesh.lg_class, lg_class) {
    struct ggeom* gp;
    LIST_FOREACH(gp, &cls->lg_geom, lg_geom) {
      struct gprovider* pp;
      LIST_FOREACH(pp, &gp->lg_provider, lg_provider) {
        provider_names[pp->lg_id] = pp->lg_name ? pp->lg_name : "";
      }
    }
  }

  // Second pass: LABEL-class providers expose a filesystem/partition label as
  // their provider name, attached via a consumer to the underlying provider.
  LIST_FOREACH(cls, &mesh.lg_class, lg_class) {
    if (cls->lg_name == nullptr) {
      continue;
    }
    std::string cname = cls->lg_name;
    if (cname != "LABEL" && cname != "PART") {
      continue;
    }
    struct ggeom* gp;
    LIST_FOREACH(gp, &cls->lg_geom, lg_geom) {
      // For PART class, each provider has rawuuid/label config attached to it.
      if (cname == "PART") {
        struct gprovider* pp;
        LIST_FOREACH(pp, &gp->lg_provider, lg_provider) {
          std::string n = pp->lg_name ? pp->lg_name : "";
          if (n.empty()) {
            continue;
          }
          std::string uuid = gconfigGet(&pp->lg_config, "rawuuid");
          std::string label = gconfigGet(&pp->lg_config, "label");
          if (!uuid.empty()) {
            uuids_for[n] = uuid;
          }
          if (!label.empty()) {
            labels_for[n] = label;
          }
        }
        continue;
      }
      // LABEL: each geom is attached (via a consumer) to one underlying
      // provider; the geom's lg_name *is* the label, and the geom contains
      // one or more providers like /dev/ufs/myrootfs, /dev/gpt/swap, etc.
      struct gconsumer* cp;
      std::string parent_name;
      LIST_FOREACH(cp, &gp->lg_consumer, lg_consumer) {
        if (cp->lg_provider != nullptr) {
          parent_name = provider_names[cp->lg_provider->lg_id];
          break;
        }
      }
      if (parent_name.empty()) {
        continue;
      }
      // LABEL geom name has the form "<subclass>/<label>" (e.g.
      // "ufs/myrootfs"); strip subclass for the label string.
      std::string lab = gp->lg_name ? gp->lg_name : "";
      auto slash = lab.find('/');
      if (slash != std::string::npos) {
        lab = lab.substr(slash + 1);
      }
      if (!lab.empty()) {
        labels_for[parent_name] = lab;
      }
    }
  }

  // Honour name= predicate so SELECT … WHERE name = '/dev/ada0' is cheap.
  auto wanted = context.constraints["name"].getAll(EQUALS);

  // Emit one row per provider across DISK + PART (the two classes the
  // upstream block_devices table cares about — LABEL/SWAP/etc. would be
  // duplicates pointing at the same media).
  LIST_FOREACH(cls, &mesh.lg_class, lg_class) {
    if (cls->lg_name == nullptr) {
      continue;
    }
    std::string cname = cls->lg_name;
    if (cname != "DISK" && cname != "PART") {
      continue;
    }
    struct ggeom* gp;
    LIST_FOREACH(gp, &cls->lg_geom, lg_geom) {
      struct gprovider* pp;
      LIST_FOREACH(pp, &gp->lg_provider, lg_provider) {
        std::string n = pp->lg_name ? pp->lg_name : "";
        if (n.empty()) {
          continue;
        }
        std::string devpath = "/dev/" + n;
        if (!wanted.empty() && wanted.count(devpath) == 0 &&
            wanted.count(n) == 0) {
          continue;
        }
        // Parent: for partitions, the consumer points at the parent disk.
        std::string parent;
        struct gconsumer* cp;
        LIST_FOREACH(cp, &gp->lg_consumer, lg_consumer) {
          if (cp->lg_provider != nullptr) {
            auto it = provider_names.find(cp->lg_provider->lg_id);
            if (it != provider_names.end()) {
              parent = "/dev/" + it->second;
              break;
            }
          }
        }
        Row r;
        r["name"] = devpath;
        r["parent"] = parent;
        // DISK class exposes descr/ident config (vendor/model/serial).
        if (cname == "DISK") {
          std::string descr = gconfigGet(&gp->lg_config, "descr");
          r["model"] = descr;
          r["serial"] = gconfigGet(&gp->lg_config, "ident");
          r["type"] = "disk";
        } else {
          // PART: provider's own config has "type" (e.g. freebsd-ufs).
          r["type"] = gconfigGet(&pp->lg_config, "type");
        }
        r["size"] = BIGINT((int64_t)pp->lg_mediasize);
        r["block_size"] = INTEGER((int32_t)pp->lg_sectorsize);
        auto uit = uuids_for.find(n);
        if (uit != uuids_for.end()) {
          r["uuid"] = uit->second;
        }
        auto lit = labels_for.find(n);
        if (lit != labels_for.end()) {
          r["label"] = lit->second;
        }
        results.push_back(r);
      }
    }
  }

  geom_deletetree(&mesh);
  return results;
}

} // namespace tables
} // namespace osquery

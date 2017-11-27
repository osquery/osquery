#define LIBDPKG_VOLATILE_API

extern "C" {
#include <dpkg/dpkg-db.h>
#include <dpkg/dpkg.h>
#include <dpkg/pkg-array.h>
#include <dpkg/parsedump.h>
}

#include <osquery/query.h>

//TODO move this to tables/system/linux
namespace osquery {

void w_revision(struct varbuf *vb,
                const struct pkginfo *pkg,
                const struct pkgbin *pkgbin,
                enum fwriteflags flags,
                const struct fieldinfo *fip);

int pkg_sorter(const void *a, const void *b);

void dpkg_setup(struct pkg_array *packages);

void dpkg_teardown(struct pkg_array *packages);
}

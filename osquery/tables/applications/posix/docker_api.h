#include <boost/property_tree/ptree.hpp>

#include <osquery/tables.h>

namespace pt = boost::property_tree;

namespace osquery {
namespace tables {
bool checkConstraintValue(const std::string& str);
Status dockerApi(const std::string& uri, pt::ptree& tree);
}
}

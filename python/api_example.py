#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

import sys
import osquery

@osquery.register_plugin
class MyLoggerPlugin(osquery.LoggerPlugin):
    def name(self):
        return "my_logger"

    def log(self, value):
        print("[+] %s" % value)

@osquery.register_plugin
class MyConfigPlugin(osquery.ConfigPlugin):
    def name(self):
        return "my_config"

    def content(self):
        return {
            "schedule": {
                "foo": {
                    "query": "select * from foobar",
                    "interval": 5,
                },
            },
        }

@osquery.register_plugin
class MyTablePlugin(osquery.TablePlugin):
    def name(self):
        return "foobar"

    def columns(self):
        return [
            osquery.TableColumn(name="foo", type=osquery.STRING),
            osquery.TableColumn(name="baz", type=osquery.STRING),
        ]

    def generate(self, context):
        query_data = []

        for i in range(5):
            row = {}
            row["foo"] = "bar"
            row["baz"] = "baz"
            query_data.append(row)

        return query_data

if __name__ == "__main__":
    osquery.start_extension()

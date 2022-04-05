import json
import random
import test_base
import os
import utils


def allowed_platform(qp):
    if qp in ["all", "any"]:
        return True
    if len(qp) == 0:
        return True

    curr_platform = utils.platform()

    if (curr_platform == "linux" or curr_platform == "darwin") and qp.find(
        "posix"
    ) >= 0:
        return True

    return qp.find(curr_platform) >= 0


class QueryPacksTests(test_base.QueryTester):
    def test_pack_queries(self):
        packs = {}
        PACKS_DIR = test_base.TEST_CONFIGS_DIR + "/packs"
        print(PACKS_DIR)
        for root, dirs, files in os.walk(PACKS_DIR):
            for name in files:
                with open(os.path.join(PACKS_DIR, name), "r") as fh:
                    content = fh.read()
                    content = content.replace("\\\n", "")
                    packs[name] = json.loads(content)
        for name, pack in packs.items():
            if "queries" not in pack:
                continue

            if "platform" in pack and not allowed_platform(pack["platform"]):
                continue

            print("Executing queries in pack: %s" % name)

            queries = []
            for query_name, query in pack["queries"].items():
                qp = query["platform"] if "platform" in query else ""
                if allowed_platform(qp):
                    queries.append(query["query"])
            self._execute_set(queries)
            print("")


if __name__ == "__main__":
    module = test_base.Tester()

    test_base.CONFIG["options"][
        "extensions_socket"
    ] = test_base.TEMP_DIR + "/osquery-%d.em" % (random.randint(1000, 9999))

    # Find and import the thrift-generated python interface
    test_base.loadThriftFromBuild(test_base.ARGS.build)
    module.run()

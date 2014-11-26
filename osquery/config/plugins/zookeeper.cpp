#include "osquery/config/plugin.h"
#include "osquery/flags.h"

#include <iostream>
#include <zookeeper/zookeeper.h>
#include <glog/logging.h>

using osquery::Status;

namespace osquery {
    int connected = 0, config_read = 0;
    // const char* osquery_path = "/osquery/config";
    std::string config;

    DEFINE_osquery_flag(string,
                        zk_hosts,
                        "127.0.0.1:2181",
                        "Comma seperated zk <host:port>,<host:port>");

    DEFINE_osquery_flag(string, zk_path, "/osquery/config", "Config path /osquery/myconfig");

    /**
     * Watcher we use to process session events. In particular,
     * when it receives a ZOO_CONNECTED_STATE event, we set the
     * connected variable so that we know that the session has
     * been established.
     */
    void main_watcher(zhandle_t *zkh,
                       int type,
                       int state,
                       const char *path,
                       void* context) {
        /*
         * zookeeper_init might not have returned, so we
         * use zkh instead.
         */
        if (type == ZOO_SESSION_EVENT) {
            if (state == ZOO_CONNECTED_STATE) {
                connected = 1;
                // printf("zookeeper client connected.\n");
                LOG(INFO) << "zookeeper client connected.";
            } else if (state == ZOO_AUTH_FAILED_STATE ) {
                connected = 0;
                LOG(INFO) << "zookeeper client not connected.";
            } else if (state == ZOO_EXPIRED_SESSION_STATE) {
                connected = 0;
                zookeeper_close(zkh);
            }
        }
    }

    void on_read_completion(int rc,
                            const char *value,
                            int value_len,
                            const struct Stat *stat,
                            const void *data) {
        switch(rc) {
            case ZOK:
                config.reserve(value_len);
                config.assign(value, value_len);
                break;
            default:
                LOG(ERROR) << "something went wrong: " << rc;
                break;
        }
        config_read = 1;
    }

    class ZookeeperConfigPlugin : public ConfigPlugin {
        public:
            virtual std::pair<osquery::Status, std::string> genConfig() {
                zhandle_t* zk_handle;
                zoo_set_debug_level(ZOO_LOG_LEVEL_ERROR);
                zk_handle = zookeeper_init(FLAGS_zk_hosts.c_str(), main_watcher, 15000, NULL, NULL, 0);

                //TODO elegant ways of doing this? Because the ZK client is async
                while(!connected) sleep(1);

                // zoo_aget(zk_handle, osquery_path, 0, on_read_completion, NULL);
                zoo_aget(zk_handle, FLAGS_zk_path.c_str(), 0, on_read_completion, NULL);

                //TODO elegant ways of doing this?
                while(!config_read) sleep(1);

                zookeeper_close(zk_handle);
                return std::make_pair(Status(0, "OK"), config);
            }
    };

REGISTER_CONFIG_PLUGIN("zookeeper",
                       std::make_shared<osquery::ZookeeperConfigPlugin>());
}

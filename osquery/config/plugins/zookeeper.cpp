#include <iostream>
#include <zookeeper/zookeeper.h>
#include <glog/logging.h>

#include "osquery/config/plugin.h"
#include "osquery/flags.h"

using osquery::Status;

namespace osquery {

    typedef struct zkCtx {
        int connected;
        int config_read;
        char *config;
    } zkCtx;

    DEFINE_osquery_flag(string,
                        zk_hosts,
                        "127.0.0.1:2181",
                        "Comma seperated zk <host:port>,<host:port>");

    DEFINE_osquery_flag(string, zk_path, "/osquery/config", "Config path /osquery/myconfig");

    class ZookeeperConfigPlugin : public ConfigPlugin {
        private:
            /**
             * Watcher we use to process session events. In particular,
             * when it receives a ZOO_CONNECTED_STATE event, we set the
             * connected variable so that we know that the session has
             * been established.
             */
            static void main_watcher(zhandle_t *zkh,
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
                        ((zkCtx *) context)->connected = 1;
                        VLOG(1) << "zookeeper client connected.";
                    } else if (state == ZOO_AUTH_FAILED_STATE ) {
                        ((zkCtx *) context)->connected = 0;
                        LOG(ERROR) << "zookeeper client not connected.";
                    } else if (state == ZOO_EXPIRED_SESSION_STATE) {
                        ((zkCtx *) context)->connected = 0;
                        zookeeper_close(zkh);
                    }
                }
            }

        private:
            static void on_read_completion(int rc,
                                    const char *value,
                                    int value_len,
                                    const struct Stat *stat,
                                    const void *data) {
                std::string _config;
                switch(rc) {
                    case ZOK:
                        ((zkCtx *) data)->config = (char *) malloc(value_len * sizeof(char));
                        _config.reserve(value_len);
                        _config.assign(value, value_len);
                        strncpy(((zkCtx *) data)->config, _config.c_str(), value_len);
                        break;
                    default:
                        LOG(ERROR) << "something went wrong: " << rc;
                        break;
                }
                ((zkCtx *) data)->config_read = 1;
            }

        public:
            virtual std::pair<osquery::Status, std::string> genConfig() {
                zhandle_t *zk_handle;
                zkCtx *zk_ctx = (zkCtx *) calloc(1, sizeof(zkCtx));

                zoo_set_debug_level(ZOO_LOG_LEVEL_ERROR);
                zk_handle = zookeeper_init(FLAGS_zk_hosts.c_str(), main_watcher, 15000, 0, (void *) zk_ctx, 0);

                //TODO elegant ways of doing this? Because the ZK client is async
                while(!zk_ctx->connected) sleep(1);

                zoo_aget(zk_handle, FLAGS_zk_path.c_str(), 0, on_read_completion, (const void *) zk_ctx);

                //TODO elegant ways of doing this?
                while(!zk_ctx->config_read) sleep(1);

                zookeeper_close(zk_handle);
                return std::make_pair(Status(0, "OK"), std::string(zk_ctx->config));
            }
    };

REGISTER_CONFIG_PLUGIN("zookeeper",
                       std::make_shared<osquery::ZookeeperConfigPlugin>());
}

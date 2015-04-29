#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from abc import ABCMeta, abstractmethod
from collections import namedtuple

try:
    from thrift import Thrift
    from thrift.transport import TSocket
    from thrift.transport import TTransport
    from thrift.protocol import TBinaryProtocol
    from thrift.server import TServer
except ImportError:
    print ("Cannot import thrift: pip install thrift?")
    exit(1)

import osquery.extensions.Extension
import osquery.extensions.ExtensionManager
import osquery.extensions.ttypes

DEFAULT_SOCKET_PATH = "/var/osquery/osquery.em"

class Singleton(object):
    _instance = None

    def __new__(self, *args, **kwargs):
        if not self._instance:
            self._instance = super(Singleton, self).__new__(
                                   self, *args, **kwargs)
        return self._instance

class ExtensionClient:
    transport = None

    def __init__(self, path=DEFAULT_SOCKET_PATH, uuid=None):
        self.path = path
        if uuid:
            self.path += ".%s" % str(uuid)
        transport = TSocket.TSocket(unix_socket=self.path)
        transport = TTransport.TBufferedTransport(transport)
        self.protocol = TBinaryProtocol.TBinaryProtocol(transport)
        self.transport = transport

    def close(self):
        if self.transport:
            self.transport.close()

    def open(self):
        '''Attempt to open the UNIX domain socket.'''
        try:
            self.transport.open()
        except Exception as e:
            return False
        return True

    def extension_manager_client(self):
        '''Return an extension manager (osquery core) client.'''
        return osquery.extensions.ExtensionManager.Client(self.protocol)

    def extension_client(self):
        '''Return an extension (osquery extension) client.'''
        return Extension.Client(self.protocol)

class ExtensionManager(Singleton, osquery.extensions.Extension.Iface):
    _plugins = {}
    _registry = {}

    def add_plugin(self, plugin):
        obj = plugin()
        if obj.registry_name() not in self._registry:
            self._registry[obj.registry_name()] = {}

        if obj.registry_name() not in self._plugins:
            self._plugins[obj.registry_name()] = {}

        if obj.name() not in self._registry[obj.registry_name()]:
            self._registry[obj.registry_name()][obj.name()] = obj.routes()

        if obj.name() not in self._plugins[obj.registry_name()]:
            self._plugins[obj.registry_name()][obj.name()] = obj

    def registry(self):
        return self._registry

    def ping(self):
        print("[+] ping")
        return osquery.extensions.ttypes.ExtensionStatus(code=0,
                                                         message="OK")

    def call(self, registry, item, request):
        print("[+] call %s %s" % (registry, item))
        response = self._plugins[registry][item].generate(request)
        return osquery.extensions.ttypes.ExtensionResponse(
            status=osquery.extensions.ttypes.ExtensionStatus(code=0,
                                                             message="OK",),
            response=response,
        )

def register_plugin(plugin):
    em = ExtensionManager()
    em.add_plugin(plugin)

def start_extension(path=DEFAULT_SOCKET_PATH):
    em = ExtensionManager()
    client = ExtensionClient(path=DEFAULT_SOCKET_PATH)
    client.open()
    emc = client.extension_manager_client()

    info = osquery.extensions.ttypes.InternalExtensionInfo(
        name = "XXX NAME",
    )

    status = emc.registerExtension(
        info=info,
        registry=em.registry(),
    )

    if status.code is not 0:
        raise RuntimeError(status.message)

    handler = em
    processor = osquery.extensions.Extension.Processor(handler)
    transport = transport = TSocket.TServerSocket(
        unix_socket=DEFAULT_SOCKET_PATH + "." + str(status.uuid))
    tfactory = TTransport.TBufferedTransportFactory()
    pfactory = TBinaryProtocol.TBinaryProtocolFactory()
    server = TServer.TSimpleServer(processor, transport, tfactory, pfactory)
    server.serve()

class BasePlugin(Singleton):
    __metaclass__ = ABCMeta

    @abstractmethod
    def name(self):
        raise NotImplementedError

    def routes(self):
        return []

class LoggerPlugin(BasePlugin):
    __metaclass__ = ABCMeta

    def registry_name(self):
        return "logger"

    @abstractmethod
    def log(self, value):
        raise NotImplementedError


class ConfigPlugin(BasePlugin):
    __metaclass__ = ABCMeta

    def registry_name(self):
        return "config"

    @abstractmethod
    def content(self):
        raise NotImplementedError


class TablePlugin(BasePlugin):
    __metaclass__ = ABCMeta

    def registry_name(self):
        return "table"

    def routes(self):
        routes = []
        for column in self.columns():
            route = {
                "name": column.name,
                "type": column.type,
            }
            routes.append(route)
        return routes

    @abstractmethod
    def columns(self):
        raise NotImplementedError

    @abstractmethod
    def generate(self, context):
        raise NotImplementedError

STRING = "TEXT"
INTEGER = "INTEGER"

TableColumn = namedtuple("TableColumn", ["name", "type"])

#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from abc import ABCMeta, abstractmethod
from collections import namedtuple
import socket

try:
    from thrift import Thrift
    from thrift.transport import TSocket
    from thrift.transport import TTransport
    from thrift.protocol import TBinaryProtocol
    from thrift.server import TServer
except ImportError:
    print("Cannot import thrift: pip install thrift")
    exit(1)

try:
    import argparse
except ImportError:
    print("Cannot import argparse: pip install argparse")
    exit(1)

import osquery.extensions.Extension
import osquery.extensions.ExtensionManager
import osquery.extensions.ttypes

DEFAULT_SOCKET_PATH = "/var/osquery/osquery.em"
"""The default path for osqueryd sockets"""

class Singleton(object):
    """A simple singleton base class"""
    _instance = None

    def __new__(self, *args, **kwargs):
        """Override __new__ to implement custom instantiation"""
        if not self._instance:
            self._instance = super(Singleton, self).__new__(
                                   self, *args, **kwargs)
        return self._instance

class ExtensionClient:
    """A client for connecting to an existing extension manager socket"""

    _transport = None

    def __init__(self, path=DEFAULT_SOCKET_PATH, uuid=None):
        """
        Keyword arguments:
        path -- the path of the extension socket to connect to
        uuid -- the additional UUID to use when constructing the socket path
        """
        self.path = path
        if uuid:
            self.path += ".%s" % str(uuid)
        transport = TSocket.TSocket(unix_socket=self.path)
        transport = TTransport.TBufferedTransport(transport)
        self.protocol = TBinaryProtocol.TBinaryProtocol(transport)
        self._transport = transport

    def close(self):
        """Close the extension client connection"""
        if self.transport:
            self.transport.close()

    def open(self):
        """Attempt to open the UNIX domain socket"""
        self.transport.open()

    def extension_manager_client(self):
        """Return an extension manager (osquery core) client."""
        return osquery.extensions.ExtensionManager.Client(self.protocol)

    def extension_client(self):
        """Return an extension (osquery extension) client."""
        return Extension.Client(self.protocol)

class ExtensionManager(Singleton, osquery.extensions.Extension.Iface):
    """The thrift server for handling extension requests

    An extension's manager is responsible for maintaining the state of
    registered plugins, broadcasting the registry of those plugins to the
    core's extension manager and fielding requests that come in on the
    extension's socket.
    """
    _plugins = {}
    _registry = {}

    def add_plugin(self, plugin):
        """Register a plugin with the extension manager. In order for the
        extension manager to broadcast a plugin, it must be added using this
        interface.

        Keyword arguments:
        plugin -- the plugin class to register
        """

        # First, we create an instance of the plugin. All plugins are
        # singletons, so this instance will be long-lived.
        obj = plugin()


        # When the extension manager broadcasts it's registry to core's
        # extension manager, the data structure should follow a specific
        # format. Whenever we add a plugin, we need to update the internal
        # _registry instance variable, which will be sent to core's extension
        # manager once the extension has been started
        if obj.registry_name() not in self._registry:
            self._registry[obj.registry_name()] = {}
        if obj.name() not in self._registry[obj.registry_name()]:
            self._registry[obj.registry_name()][obj.name()] = obj.routes()

        # The extension manager needs a way to route calls to the appropriate
        # implementation class. We maintain references to the plugin's
        # singleton instantiation in the _plugins instance variable. The
        # _plugins member has the same general structure as _registry, but
        # instead of pointing to the plugin's routes, it points to the plugin
        # implementation object
        if obj.registry_name() not in self._plugins:
            self._plugins[obj.registry_name()] = {}
        if obj.name() not in self._plugins[obj.registry_name()]:
            self._plugins[obj.registry_name()][obj.name()] = obj

    def registry(self):
        """Accessor for the internal _registry member variable"""
        return self._registry

    def ping(self):
        """Lightweight health verification

        The core osquery extension manager will periodically "ping" each
        extension that has connected to it to ensure that the extension is
        still active and can field requests, if necessary.
        """
        return osquery.extensions.ttypes.ExtensionStatus(code=0,
                                                         message="OK")

    def call(self, registry, item, request):
        """The entry-point for plugin requests

        When a plugin is accessed from another process, osquery core's
        extension manager will send a thrift request to the implementing
        extension manager's call method.

        Arguments:
        registry -- a string representing what registry is being accessed.
            for config plugins this is "config", for table plugins this is
            "table", etc.
        item -- the registry item that is being requested. this is the "name"
            of your plugin. for example, this would be the exact name of the
            SQL table, if the plugin was a table plugin.
        """
        try:
            response = self._plugins[registry][item].generate(request)
        except KeyError:
            message = "Extension registry does not contain requested plugin"
            return osquery.extensions.ttypes.ExtensionResponse(
                status=osquery.extensions.ttypes.ExtensionStatus(
                    code=1,
                    message=message,),
                response=[],
            )
        return osquery.extensions.ttypes.ExtensionResponse(
            status=osquery.extensions.ttypes.ExtensionStatus(code=0,
                                                             message="OK",),
            response=response,
        )

def register_plugin(plugin):
    """Decorator wrapper used for registering a plugin class

    To register your plugin, add this decorator to your plugin's implementation
    class:

        @osquery.register_plugin
        class MyTablePlugin(osquery.TablePlugin):
    """
    em = ExtensionManager()
    em.add_plugin(plugin)

def parse_cli_params():
    """Parse CLI parameters passed to the extension executable"""
    parser = argparse.ArgumentParser(description=(
        "osquery python api"
    ))
    parser.add_argument(
        "--socket",
        type=str,
        default=DEFAULT_SOCKET_PATH,
        help="Path to the extensions UNIX domain socket")
    return parser.parse_args()

def start_extension(name="", version="", sdk_version="", min_sdk_version=""):
    """Start your extension by communicating with osquery core and starting
    a thrift server.

    Keyword arguments:
    name -- the name of your extension
    version -- the version of your extension
    sdk_version -- the version of the osquery SDK used to build this extension
    min_sdk_version -- the minimum version of the osquery SDK that you can use
    """
    args = parse_cli_params()
    client = ExtensionClient(path=args.socket)
    client.open()
    em = ExtensionManager()

    # try connecting to the desired osquery core extension manager socket
    try:
        status = client.extension_manager_client().registerExtension(
            info=osquery.extensions.ttypes.InternalExtensionInfo(
                name=name,
                version=version,
                sdk_version=sdk_version,
                min_sdk_version=min_sdk_version,
            ),
            registry=em.registry(),
        )
    except socket.error:
        message = "Could not connect to %s" % args.socket
        raise osquery.extensions.ttypes.ExtensionException(
            code=1,
            message=message,
        )

    if status.code is not 0:
        raise osquery.extensions.ttypes.ExtensionException(
            code=1,
            message=status.message,
        )

    # start a thrift server listening at the path dictated by the uuid returned
    # by the osquery core extension manager
    processor = osquery.extensions.Extension.Processor(em)
    transport = transport = TSocket.TServerSocket(
        unix_socket=args.socket + "." + str(status.uuid))
    tfactory = TTransport.TBufferedTransportFactory()
    pfactory = TBinaryProtocol.TBinaryProtocolFactory()
    server = TServer.TSimpleServer(processor, transport, tfactory, pfactory)
    server.serve()

class BasePlugin(Singleton):
    """All osquery plugins should inherit from BasePlugin"""
    __metaclass__ = ABCMeta

    @abstractmethod
    def name(self):
        """The name of your plugin.

        This must be implemented by your plugin.
        """
        raise NotImplementedError

    def routes(self):
        """The routes that should be broadcasted by your plugin"""
        return []

class LoggerPlugin(BasePlugin):
    """All logger plugins should inherit from LoggerPlugin"""
    __metaclass__ = ABCMeta

    def registry_name(self):
        """The name of the registry type for logger plugins.

        Do not override this method."""
        return "logger"

    @abstractmethod
    def log(self, value):
        """The implementation of your logger plugin.

        This must be implemented by your plugin.

        Arguments:
        value -- the string to log
        """
        raise NotImplementedError


class ConfigPlugin(BasePlugin):
    """All config plugins should inherit from ConfigPlugin"""
    __metaclass__ = ABCMeta

    def registry_name(self):
        """The name of the registry type for config plugins.

        Do not override this method."""
        return "config"

    @abstractmethod
    def content(self):
        """The implementation of your config plugin.

        This must be implemented by your plugin.
        """
        raise NotImplementedError


class TablePlugin(BasePlugin):
    """All table plugins should inherit from TablePlugin"""
    __metaclass__ = ABCMeta

    def registry_name(self):
        """The name of the registry type for table plugins.

        Do not override this method."""
        return "table"

    def routes(self):
        """The routes that will be broadcasted for table plugins

        Do not override this method.
        """
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
        """The columns of your table plugin.

        This method should return an array of osquery.TableColumn instances.

        Consider the following example:

            class MyTablePlugin(osquery.TablePlugin):
                def columns(self):
                    return [
                        osquery.TableColumn(name="foo", type=osquery.STRING),
                        osquery.TableColumn(name="baz", type=osquery.STRING),
                    ]

        This must be implemented by your plugin.
        """
        raise NotImplementedError

    @abstractmethod
    def generate(self, context):
        """The implementation of your table plugin.

        This method should return a list of dictionaries, such that each
        dictionary has a key corresponding to each of your table's columns.

        Consider the following example:

            class MyTablePlugin(osquery.TablePlugin):
                def generate(self, context):
                    query_data = []

                    for i in range(5):
                        row = {}
                        row["foo"] = "bar"
                        row["baz"] = "boo"
                        query_data.append(row)

                    return query_data

        This must be implemented by your plugin.
        """
        raise NotImplementedError

STRING = "TEXT"
"""The text SQL column type"""

INTEGER = "INTEGER"
"""The integer SQL column type"""

TableColumn = namedtuple("TableColumn", ["name", "type"])
"""An object which allows you to define the name and type of a SQL column"""

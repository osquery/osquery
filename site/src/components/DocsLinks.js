/** @jsx React.DOM */

'use strict';

var React = require('react');

var Router = require('react-router-component');
var InternalLink = Router.Link;
var QuickLinks = require('./QuickLinks');

var DocsLinks = React.createClass({
  render: function () {
    return (
      <div className="bs-docs-sections">
        <h3 className="page-header">Install Guide</h3>
        <ul>
          <li><h4><InternalLink href="/docs/install-osx.html">OS X</InternalLink></h4></li>
          <li><h4><InternalLink href="/docs/install-linux.html">Linux</InternalLink></h4></li>
        </ul>

        <h3 className="page-header">User's Guide</h3>
        <ul>
          <li><h4><InternalLink href="/docs/users-introduction.html">Introduction</InternalLink></h4></li>
          <li><h4><InternalLink href="/docs/using-osqueryi.html">Using osqueryi</InternalLink></h4></li>
          <li><h4><InternalLink href="/docs/using-osqueryd.html">Using osqueryd</InternalLink></h4></li>
          <li><h4><InternalLink href="/docs/public-api.html">Public API</InternalLink></h4></li>
        </ul>

        <h3 className="page-header">Deployment Guide</h3>
        <ul>
          <li><h4><InternalLink href="/docs/deployment-introduction.html">Introduction</InternalLink></h4></li>
          <li><h4><InternalLink href="/docs/distributing-osquery.html">Distributing osquery internally</InternalLink></h4></li>
          <li><h4><InternalLink href="/docs/log-aggregation.html">Gathering and analyzing logs</InternalLink></h4></li>
          <li><h4><InternalLink href="/docs/creating-custom-tables.html">Creating custom tables</InternalLink></h4></li>
          <li><h4><InternalLink href="/docs/registering-logger-plugins.html">Using internal logging infrastructure</InternalLink></h4></li>
          <li><h4><InternalLink href="/docs/registering-config-plugins.html">Using internal config distribution infrastructure</InternalLink></h4></li>
        </ul>

        <h3 className="page-header">Developer's Guide</h3>

        <ul>

          <li><h4>Introduction</h4></li>
          <ul>
            <li><h4><InternalLink href="/docs/building-the-code.html">Building the code</InternalLink></h4></li>
            <li><h4><InternalLink href="/docs/contributing-code.html">Contributing code</InternalLink></h4></li>
            <li><h4><InternalLink href="/docs/formatting-code.html">Formatting your code</InternalLink></h4></li>
            <li><h4><InternalLink href="/docs/unit-tests.html">Unit tests</InternalLink></h4></li>
            <li><h4><InternalLink href="/docs/creating-custom-tables.html">Creating a new table</InternalLink></h4></li>
          </ul>

          <li><h4>Project Documentation</h4></li>
          <ul>
            <li><h4><InternalLink href="/docs/current-goals.html">Current goals</InternalLink></h4></li>
          </ul>

          <li><h4>Performance</h4></li>
          <ul>
            <li><h4><InternalLink href="/docs/performance-overview.html">Overview</InternalLink></h4></li>
            <li><h4><InternalLink href="/docs/memory-leaks.html">Testing for memory leaks</InternalLink></h4></li>
            <li><h4><InternalLink href="/docs/creating-benchmarks.html">Creating benchmarks</InternalLink></h4></li>
          </ul>

          <li><h4>Registering new plugins</h4></li>
          <ul>
            <li><h4><InternalLink href="/docs/registering-logger-plugins.html">Registering logger plugins</InternalLink></h4></li>
            <li><h4><InternalLink href="/docs/registering-config-plugins.html">Registering config plugins</InternalLink></h4></li>
          </ul>

          <li><h4>Examples</h4></li>
          <ul>
            <li><h4><InternalLink href="/docs/examples/reading-a-file.html">Reading files</InternalLink></h4></li>
            <li><h4><InternalLink href="/docs/examples/reading-a-plist.html">Reading property lists</InternalLink></h4></li>
            <li><h4><InternalLink href="/docs/examples/logging.html">Logging and metrics collection</InternalLink></h4></li>
          </ul>

          <li><h4>Low level details</h4></li>
          <ul>
            <li><h4><InternalLink href="/docs/virtual-tables.html">Virtual table architecture</InternalLink></h4></li>
            <li><h4><InternalLink href="/docs/using-rocksdb.html">Using RocksDB</InternalLink></h4></li>
            <li><h4><InternalLink href="/docs/objc-cross-compilation.html">Cross-compiling C++ and Objective-C</InternalLink></h4></li>
            <li><h4><InternalLink href="/docs/component-registration.html">Component registration</InternalLink></h4></li>
          </ul>

          <li><h4>Packaging</h4></li>
          <ul>
            <li><h4><InternalLink href="/docs/creating-packages.html">Creating packages</InternalLink></h4></li>
            <li><h4><InternalLink href="/docs/third-party-code.html">Third-party code</InternalLink></h4></li>
          </ul>
        </ul>
      </div>

    );
  }
});

module.exports = DocsLinks;

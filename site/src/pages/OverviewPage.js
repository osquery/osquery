/** @jsx React.DOM */

'use strict';

var React = require('react');

var BasePage = require('./BasePage')
var PageHeader = require('../components/PageHeader');
var PageFooter = require('../components/PageFooter');
var PageContainer = require('../components/PageContainer')

var Page = React.createClass({
  render: function () {
    return (
      <BasePage pageName="overview">
        <PageHeader
          title="Overview"
          subTitle="What osquery can do for you." />

        <PageContainer>
            <p className="lead"> osquery exposes an operating system as a
            high-performance relational database. This allows you to write
            SQL-based queries to explore operating system data on a variety of
            platforms. </p>

            <h3 className="page-header">Interactive SQL</h3>

            <p className="lead"> The <strong>interactive query console</strong>,
            osqueryi, gives you a SQL interface to try out new queries and
            explore your operating system. With the power of a complete SQL
            language and dozens of useful tables built-in, osqueryi is an
            invaluable tool when performing incident response, diagnosing an
            systems operations problem, troubleshooting a performance issue, etc.
            </p>

            <h3 className="page-header">Distributed Monitoring</h3>

            <p className="lead"> The <strong>high-performance, low-footprint
            distributed host monitoring daemon</strong>, osqueryd, allows you to
            schedule queries to be executed across your entire infrastructure.
            The daemon takes care of aggregating the query results over time and
            generates logs which indicate state changes in your infrastructure.
            You can use this to maintain insight into the security, performance,
            configuration and state of your entire infrastructure. osqueryd's
            logging can integrate right into your internal log aggregation
            pipeline, regardless of your technology stack, via a robust plugin
            architecture. </p>

            <h3 className="page-header">Performance is a Feature</h3>

            <p className="lead"> A top-level goal of osquery is for it to be
            performant enough to run on production infrastructure with the
            smallest possible footprint. The core osquery team at Facebook puts a
            lot of effort into ensuring that all code is rigorously benchmarked
            and tested for memory leaks. All systems operations in osquery use
            underlying systems APIs exclusively. For example, the kextstat table
            in OS X uses the same underlying core APIs as the kextstat
            command.</p>

            <h3 className="page-header">Deployment is Easy</h3>

            <p className="lead"> To assist with the rollout process, the osquery
            wiki has <strong> detailed documentation on internal deployment
            </strong>. osquery was built so that every environment specific
            aspect of the toolchain can be hot-swapped at run-time with custom
            plugins. Use these interfaces to deeply integrate osquery into your
            infrastructure if one of the several existing plugins don't suit your
            needs. </p>

            <p className="lead"> Additionally, osquery comes with <strong> native
            packages for all supported operating systems </strong>. There's great
            tooling and documentation around creating packages, so packaging and
            deploying your custom osquery tools can be just as easy too. </p>

            <h3 className="page-header"> Monitor OS X clients as well as Linux servers </h3>

            <p className="lead"> osquery is <strong>cross platform</strong>. Even
            though osquery takes advantage of very low-level operating system
            APIs, you can build and use osquery on Ubuntu, Cent OS and Mac OS X.
            This has the distinct advantage of allowing you to be able to use one
            platform for monitoring complex operating system state across you're
            entire infrastructure. Monitor your corporate Mac OS X clients the
            same way you monitor your production Linux servers. </p>
        </PageContainer>
      </BasePage>
    );
  }
});

module.exports = Page;

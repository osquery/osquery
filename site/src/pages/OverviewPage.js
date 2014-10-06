/** @jsx React.DOM */

'use strict';

var React = require('react');

var BasePage = require('./BasePage')
var PageHeader = require('../components/PageHeader');
var PageFooter = require('../components/PageFooter');
var WideContainer = require('../components/WideContainer')

var Page = React.createClass({
  render: function () {
    return (
      <BasePage pageName="overview">
        <PageHeader
          title="Overview"
          subTitle="A brief introduction to what osquery can do for you." />

        <WideContainer>
          <p className="lead">osquery is an operating system instrumentation
          toolchain for *nix based hosts. osquery makes low-level operating
          system analytics and monitoring both performant and intuitive.</p>

          <h3 id="infrastructure-monitoring" className="page-header">Distributed Monitoring</h3>

          <p className="lead"> The <strong>high-performance, low-footprint
          distributed host monitoring daemon</strong>, osqueryd, allows you to
          schedule queries to be executed across your entire infrastructure.
          The daemon takes care of aggregating the query results over time and
          generates logs which indicate state changes in your infrastructure.
          You can use this to maintain insight into the security, performance,
          configuration and state of your entire infrastructure. osqueryd's
          logging can integrate right into your internal log aggregation
          pipeline, regardless of your technology stack, via a robust plugin
          architecture.</p>

        </WideContainer>
      </BasePage>
    );
  }
});

module.exports = Page;

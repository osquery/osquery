/** @jsx React.DOM */

'use strict';

var React = require('react');

var BasePage = require('./BasePage');
var Hero = require('../components/Hero');
var PageContainer = require('../components/PageContainer')

var Page = React.createClass({
  render: function () {
    return (
      <BasePage pageName="home">
        <Hero>
          <div className="bs-docs-booticon bs-docs-booticon-lg bs-docs-booticon-outline"></div>
          <p className="lead">SQL powered operating system instrumentation and analytics.</p>
        </Hero>

        <PageContainer>
          <div className="homepage-text">

            <p className="lead">osquery is an operating system instrumentation
            toolchain for *nix based hosts. osquery makes low-level operating
            system analytics and monitoring both performant and intuitive.</p>

            <p className="lead">osquery exposes an operating system as a
            high-performance relational database. This allows you to write
            SQL-based queries to explore operating system data.</p>

            <div className="showterm">
              <iframe width="100%" height="480" src="http://showterm.io/7b5f8d42ba021511e627e"></iframe>
            </div>

          </div>

        </PageContainer>
      </BasePage>
    );
  }
});

module.exports = Page;

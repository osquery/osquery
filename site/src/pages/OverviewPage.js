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

          <p className="lead">osquery exposes an operating system as a
          high-performance relational database. This allows you to write
          SQL-based queries to explore operating system data.</p>

          <div className="showterm">
            <iframe width="100%" height="480" src="http://showterm.io/7b5f8d42ba021511e627e"></iframe>
          </div>

       </PageContainer>
      </BasePage>
    );
  }
});

module.exports = Page;

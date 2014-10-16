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

          <p className="lead">With osquery, you can use SQL to query low-level
          operating system information. Under the hood, instead of tables, these
          queries dynamically execute high-performance native code. The results
          of the SQL query are transparently returned to you quickly and easily.</p>

          <p className="lead">Consider the following example, which uses osqueryi,
          the interactive query console, to execute a few SQL queries.</p>

          <div className="showterm">
            <iframe width="100%" height="480" src="http://showterm.io/7b5f8d42ba021511e627e"></iframe>
          </div>

       </PageContainer>
      </BasePage>
    );
  }
});

module.exports = Page;

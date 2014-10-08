/** @jsx React.DOM */

'use strict';

var React = require('react');

var BasePage = require('./BasePage')
var PageHeader = require('../components/PageHeader');
var PageFooter = require('../components/PageFooter');
var PageContainer = require('../components/PageContainer');
var DocsLinks = require('../components/DocsLinks');

var Page = React.createClass({
  render: function () {
    return (
      <BasePage pageName="documentation">
        <PageHeader
          title="Documentation"
          subTitle="Learn about osquery." />

        <PageContainer>
          <DocsLinks />
       </PageContainer>
      </BasePage>
    );
  }
});

module.exports = Page;

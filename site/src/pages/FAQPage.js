/** @jsx React.DOM */

'use strict';

var React = require('react');

var BasePage = require('./BasePage');
var PageHeader = require('../components/PageHeader');

var Page = React.createClass({
  render: function () {
    return (
      <BasePage pageName="faq">
        <PageHeader
          title="FAQ"
          subTitle="Frequently asked questions about osquery." />
      </BasePage>
    );
  }
});

module.exports = Page;

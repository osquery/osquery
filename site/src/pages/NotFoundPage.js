/** @jsx React.DOM */

'use strict';

var React = require('react');

var BasePage = require('./BasePage');
var PageHeader = require('../components/PageHeader');

var Page = React.createClass({
  render: function () {
    return (
      <BasePage>
        <PageHeader
          title="404"
          subTitle="Hmmm this is awkward." />
      </BasePage>
    );
  }
});

module.exports = Page;

/** @jsx React.DOM */

'use strict';

var React = require('react');

var BasePage = require('./BasePage');
var Hero = require('../components/Hero');

var Page = React.createClass({
  render: function () {
    return (
      <BasePage pageName="home">
        <Hero>
          <div className="bs-docs-booticon bs-docs-booticon-lg bs-docs-booticon-outline"></div>
          <p className="lead">SQL powered operating system instrumentation and analytics.</p>
        </Hero>
      </BasePage>
    );
  }
});

module.exports = Page;

/** @jsx React.DOM */

'use strict';

var React = require('react');

var BasePage = require('./BasePage');
var Hero = require('../components/Hero');
var LogoSpan = require('../components/LogoSpan');

var Page = React.createClass({
  render: function () {
    return (
      <BasePage pageName="home">
        <Hero>
          <LogoSpan/>
          <p className="lead">SQL powered operating system instrumentation and analytics.</p>
        </Hero>
      </BasePage>
    );
  }
});

module.exports = Page;

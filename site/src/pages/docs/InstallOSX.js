/** @jsx React.DOM */

'use strict';

var React = require('react');

var BasePage = require('../BasePage')
var PageHeader = require('../../components/PageHeader');
var PageFooter = require('../../components/PageFooter');
var DocsContainer = require('../../components/DocsContainer')
var CodeSnippet = require('../../components/CodeSnippet');

var Page = React.createClass({
  render: function () {
    return (
      <BasePage pageName="">
        <PageHeader title="Install on OS X" />

        <DocsContainer>

          <p className="lead">As of this writing (October 6, 2014), the primary supported way to
          install osquery on a personal machine is via source. Simply clone the
          repo and run the following:</p>

          <CodeSnippet file="make-commands.txt" />

          <p className="lead"> Once the project is open sourced, the plan is to
          get osquery into Homebrew so that users can use brew install osquery
          to install osquery and brew update && brew upgrade osquery to update
          to the latest stable release. </p>

       </DocsContainer>
      </BasePage>
    );
  }
});

module.exports = Page;

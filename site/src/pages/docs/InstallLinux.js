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
        <PageHeader title="Install on Linux" />

        <DocsContainer>

          <p className="lead"> In order to allow you to use and distribute
          osquery in a way that works for you and your organization, osquery
          supports several distributions of Linux. For each supported distro,
          we supply vagrant infrastructure for creating native operating system
          packages. To create a package (a deb on Ubuntu, an rpm on CentOS),
          simply turn on the vagrant instance of your operating system of
          choice:</p>

          <CodeSnippet file="vagrant-up.txt" />

          <p className="lead">The available options are:</p>

          <ul>
            <li>ubuntu14</li>
            <li>ubuntu12</li>
            <li>centos</li>
          </ul>

          <p className="lead"> Once you've logged in the vagrant box, note that
          the code is located at <code>/vagrant</code>. Simply run the following to create a
          package:</p>

          <CodeSnippet file="make-package.txt" />

          <p className="lead"> This will create a deb or an rpm (depending on
          your platform). You can then distribute and install that package
          however you please.</p>

       </DocsContainer>
      </BasePage>
    );
  }
});

module.exports = Page;

/** @jsx React.DOM */

/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant 
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

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

            <h2> What is osquery? </h2>

            <p className="lead">With osquery, you can use SQL to query
            low-level operating system information. Under the hood, instead of
            querying static tables, these queries dynamically execute
            high-performance native code. The results of the SQL query are
            transparently returned to you quickly and easily.</p>

            <p className="lead">Consider the following example, which uses osqueryi,
            the interactive query console, to execute a few SQL queries.</p>

            <div className="showterm">
              <iframe width="100%" height="480" src="http://showterm.io/65ec8d4eb3c9896815333"></iframe>
            </div>

            <h2>Install osquery</h2>

            <p className="lead">Installing osquery is easy. We maintain install
            guides for OS X and Linux on the <a
            href="https://github.com/facebook/osquery/wiki#getting-started">wiki</a>.</p>

            <h2>Who uses it?</h2>

            <p className="lead">Facebook uses osquery to gain insight into OS X
            and Linux hosts. Other notable companies also use osquery because
            of how easy it is to deploy osquery and the advanced insight into
            their infrastructure that osquery can offer them</p>

            <p className="lead"><i>“osquery is simple, lightweight and was very
            easy to integrate with the other tools we use. The deamon is easy
            to configure and the deployment process has been really easy.” -
            Bryan Eastes / Yelp</i></p>

          </div>
        </PageContainer>
      </BasePage>
    );
  }
});

module.exports = Page;

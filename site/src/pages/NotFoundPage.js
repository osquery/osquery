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

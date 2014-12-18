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

var NavMain = require('../components/NavMain');
var PageHeader = require('../components/PageHeader');
var PageFooter = require('../components/PageFooter');

var Page = React.createClass({
  render: function () {
    return (
        <div>
          <NavMain activePage={this.props.pageName} />
          {this.props.children}
          <PageFooter />
        </div>
      );
  }
});

module.exports = Page;

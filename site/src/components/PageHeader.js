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

var PageHeader = React.createClass({
  render: function () {
    return (
      <div className="bs-docs-header" id="content">
        <div className="container">
          <div className="row">
            <div className="col-md-9">
              <h1>{this.props.title}</h1>
              <p>{this.props.subTitle}</p>
            </div>
            <div className="col-md-3">
              <div className="logo-icon-md"></div>
            </div>
          </div>
        </div>
      </div>
    );
  }
});

module.exports = PageHeader;

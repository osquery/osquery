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

var WideContainer = React.createClass({
  render: function () {
    return (
      <div className="container bs-docs-container">
        <div className="row">
          <div className="col-md-12">
            <div className="bs-docs-section">
              {this.props.children}
            </div>
          </div>
        </div>
      </div>
    );
  }
});

module.exports = WideContainer;

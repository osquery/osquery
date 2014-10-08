/** @jsx React.DOM */

'use strict';

var React = require('react');

var DocsLinks = require('./DocsLinks');

var DocsContainer = React.createClass({
  render: function () {
    return (
      <div className="container bs-docs-container">
        <div className="row">

          <div className="col-md-9">
            <div className="bs-docs-section">
              {this.props.children}
            </div>
          </div>

          <div className="col-md-3">
            <div className="bs-docs-section">
              <DocsLinks/>
            </div>
          </div>

        </div>
      </div>
    );
  }
});

module.exports = DocsContainer;

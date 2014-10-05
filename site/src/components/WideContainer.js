/** @jsx React.DOM */

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

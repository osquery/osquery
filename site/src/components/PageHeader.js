/** @jsx React.DOM */

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
              <div className="logo-icon"></div>
            </div>
          </div>
        </div>
      </div>
    );
  }
});

module.exports = PageHeader;

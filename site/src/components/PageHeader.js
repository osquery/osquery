/** @jsx React.DOM */

'use strict';

var React = require('react');

var PageHeader = React.createClass({
  render: function () {
    return (
      <div className="bs-docs-header" id="content">
        <div className="container">
          <h1>{this.props.title}</h1>
          <p>{this.props.subTitle}</p>
        </div>
      </div>
      );
  }
});

module.exports = PageHeader;

/** @jsx React.DOM */

'use strict';

var React = require('react');

var QuickLinks = require('./QuickLinks');
var ListGroup = require('react-bootstrap/ListGroup');
var ListGroupItem = require('react-bootstrap/ListGroupItem');

var PageContainer = React.createClass({
  render: function () {
    return (
      <div className="container bs-docs-container">
        <div className="row">

          <div className="col-md-9">
            <div className="bs-docs-section">
              {this.props.children}
            </div>
          </div>

          <QuickLinks/>

        </div>
      </div>
    );
  }
});

module.exports = PageContainer;

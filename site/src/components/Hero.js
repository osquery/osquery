/** @jsx React.DOM */

'use strict';

var React = require('react');

var Hero = React.createClass({
  render: function () {
    return (
          <main className="bs-docs-masthead" id="content" role="main">
            <div className="container">
              {this.props.children}
            </div>
          </main>
      );
  }
});

module.exports = Hero;

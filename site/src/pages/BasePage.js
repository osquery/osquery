/** @jsx React.DOM */

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

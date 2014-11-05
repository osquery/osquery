/** @jsx React.DOM */

'use strict';

var React = require('react');
var Router = require('react-router-component');

var Navbar = require('react-bootstrap/Navbar');
var Nav = require('react-bootstrap/Nav');

var InternalLink = Router.Link;

var NAV_LINKS = {
  'overview': {
    link: '/overview/',
    title: 'Overview'
  },
  'tables': {
    link: '/tables/',
    title: 'Tables'
  }
}

var EXTERNAL_NAV_LINKS = {
  'wiki': {
    link: '//github.com/facebook/osquery/wiki',
    title: 'Documentation'
  },
  'github': {
    link: '//github.com/facebook/osquery/',
    title: 'GitHub'
  }
};

var NavMain = React.createClass({
  propTypes: {
    activePage: React.PropTypes.string
  },

  render: function () {
    var brand = <InternalLink href="/" className="navbar-brand">osquery</InternalLink>;

    return (
      <Navbar
        componentClass={React.DOM.header}
        brand={brand}
        staticTop
        className="bs-docs-nav"
        role="banner"
        toggleNavKey={0}>

        <Nav className="bs-navbar-collapse" role="navigation" key={0} id="top">
          {Object.keys(NAV_LINKS).map(this.renderNavItem)}
          {Object.keys(EXTERNAL_NAV_LINKS).map(this.renderExternalNavItem)}
        </Nav>

      </Navbar>
    );
  },

  renderExternalNavItem: function (linkName) {
    var link = EXTERNAL_NAV_LINKS[linkName];

    return (
      <li key={linkName}>
        <a href={link.link} target="_blank">{link.title}</a>
      </li>
    );
  },

  renderNavItem: function (linkName) {
    var link = NAV_LINKS[linkName];

    return (
      <li className={this.props.activePage === linkName ? 'active' : null} key={linkName}>
        <InternalLink href={link.link}>{link.title}</InternalLink>
      </li>
    );
  }
});

module.exports = NavMain;

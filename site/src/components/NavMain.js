/** @jsx React.DOM */

'use strict';

var React = require('react');

var Navbar = require('react-bootstrap/Navbar');
var Nav = require('react-bootstrap/Nav');

var NAV_LINKS = {
  'overview': {
    link: '/overview/',
    title: 'Overview'
  },
  'faq': {
    link: '/faq/',
    title: 'FAQ'
  },
  'wiki': {
    link: '//github.com/facebook/osquery/wiki',
    title: 'Wiki'
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
    var brand = <a href="/" className="navbar-brand">osquery</a>;

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
        </Nav>

      </Navbar>
    );
  },

  renderNavItem: function (linkName) {
    var link = NAV_LINKS[linkName];

    return (
        <li className={this.props.activePage === linkName ? 'active' : null} key={linkName}>
          <a href={link.link}>{link.title}</a>
        </li>
      );
  }
});

module.exports = NavMain;

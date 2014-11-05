/** @jsx React.DOM */

'use strict';

var React = require('react');
var Router = require('react-router-component');

var HomePage = require('./pages/HomePage');
var OverviewPage = require('./pages/OverviewPage');
var TablesPage = require('./pages/TablesPage');
var NotFoundPage = require('./pages/NotFoundPage');

var Tags = require('./api/Tags');

var Locations = Router.Locations;
var Location = Router.Location;
var NotFound = Router.NotFound;

var PagesHolder = React.createClass({
  render: function () {
    return (
      <Locations contextual>
        <Location path="/" handler={HomePage} />
        <Location path="/index.html" handler={HomePage} />
        <Location path="/overview/" handler={OverviewPage} />
        <Location path="/overview/index.html" handler={OverviewPage} />
        <Location path="/tables/" handler={TablesPage} />
        <Location path="/tables/index.html" handler={TablesPage} />
        <Location path="/tables/:tag" handler={TablesPage} />
        <NotFound handler={NotFoundPage} />
      </Locations>
    );
  }
});

var Root = React.createClass({
  statics: {
    getDoctype: function () {
      return '<!doctype html>';
    },

    renderToString: function (props) {
      return Root.getDoctype() +
        React.renderComponentToString(Root(props));
    },

    /**
     * Get the Base url this app sits at
     * This url is appended to all app urls to make absolute url's within the app.
     *
     * @returns {string}
     */
    getBaseUrl: function () {
      return '/';
    },

    /**
     * Get the list of pages that are renderable
     *
     * @returns {Array}
     */
    getPages: function () {
      var pages = [
        '/index.html',
        '/overview/index.html',
        '/tables/index.html',
      ];
      for (var i = 0; i < Tags.length; i++) {
        pages[pages.length] = "/tables/" + Tags[i] + ".html";
      }
      return pages;
    }
  },

  render: function () {
    // Dump out our current props to a global object via a script tag so
    // when initialising the browser environment we can bootstrap from the
    // same props as what each page was rendered with.
    var browserInitScriptObj = {
      __html:
        "window.INITIAL_PROPS = " + JSON.stringify(this.props) + ";\n" +
        // console noop shim for IE8/9
        "(function (w) {\n" +
        "  var noop = function () {};\n" +
        "  if (!w.console) {\n" +
        "    w.console = {};\n" +
        "    ['log', 'info', 'warn', 'error'].forEach(function (method) {\n" +
        "      w.console[method] = noop;\n" +
        "    });\n" +
        " }\n" +
        "}(window));\n"
    };

    return (
        <html>
          <head>
            <title>osquery</title>
            <meta http-equiv="X-UA-Compatible" content="IE=edge" />
            <meta name="viewport" content="width=device-width, initial-scale=1.0" />
            <link rel="shortcut icon" href="/assets/favicon.ico" type="image/x-icon" />
            <link rel="icon" href="/assets/favicon.ico" type="image/x-icon" />
            <link href="/vendor/bootstrap/bootstrap.css" rel="stylesheet" />
            <link href="/vendor/bootstrap/docs.css" rel="stylesheet" />
            <link href="/vendor/codemirror/codemirror.css" rel="stylesheet" />
            <link href="/vendor/codemirror/solarized.css" rel="stylesheet" />
            <link href="/vendor/codemirror/syntax.css" rel="stylesheet" />
            <link href="/assets/style.css" rel="stylesheet" />
          </head>

          <body>
            <Locations path={Root.getBaseUrl() + this.props.initialPath}>
              <Location path={Root.getBaseUrl() + '*'} handler={PagesHolder} />
            </Locations>

            <script dangerouslySetInnerHTML={browserInitScriptObj} />
            <script src="/vendor/codemirror/codemirror.js" />
            <script src="/vendor/codemirror/javascript.js" />
            <script src="/vendor/bootstrap/bootstrap.js" />
            <script src="/vendor/JSXTransformer.js" />
            <script src="/assets/bundle.js" />
          </body>
        </html>
      );
  }
});

module.exports = Root;

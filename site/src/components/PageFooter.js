/** @jsx React.DOM */

'use strict';

var React = require('react');

var PageHeader = React.createClass({
  render: function () {
    var user = 'marpaia';
    var repo = 'chef-golang';
    var github = 'https://github.com/' + user + '/' + repo;
    var license = github + '/blob/master/LICENSE';
    var issues = github + '/issues?state=open';
    var releases = github + '/releases';

    var ghbtns = 'http://ghbtns.com/github-btn.html?user=' + user + '&repo=' + repo;
    var starButton = ghbtns + '&type=watch&count=true';
    var forkButton = ghbtns + '&type=fork&count=true';
    return (
        <footer className="bs-docs-footer" role="contentinfo">
          <div className="container">
            <div className="bs-docs-social">
              <ul className="bs-docs-social-buttons">
                <li>
                  <iframe
                    className="github-btn"
                    src={starButton}
                    width={90}
                    height={20}
                    title="Star on GitHub" />
                </li>
                <li>
                  <iframe
                    className="github-btn"
                    src={forkButton}
                    width={92}
                    height={20}
                    title="Fork on GitHub" />
                </li>
              </ul>
            </div>
            <p>Code licensed under <a href={license} target="_blank">MIT</a>.</p>
            <ul className="bs-docs-footer-links muted">
              <li>·</li>
              <li><a href={github} target="_blank">GitHub</a></li>
              <li>·</li>
              <li><a href={issues} target="_blank">Issues</a></li>
              <li>·</li>
              <li><a href={releases} target="_blank">Releases</a></li>
            </ul>
          </div>
        </footer>
      );
  }
});

module.exports = PageHeader;

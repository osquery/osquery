/** @jsx React.DOM */

'use strict';

var React = require('react');

var Router = require('react-router-component');
var InternalLink = Router.Link;

var BasePage = require('./BasePage');
var PageHeader = require('../components/PageHeader');
var PageFooter = require('../components/PageFooter');
var PageContainer = require('../components/PageContainer');

var NotFoundPage = require('./NotFoundPage');
var Tags = require('../api/Tags');

var Column = React.createClass({
  render: function() {
    var column = this.props.data;
  	return (
      <tr>
        <td><code><span className="text-info">{column.name}</span></code></td>
        <td><code>{column.type}</code></td>
        <td>{column.description}</td>
      </tr>
    );
  }
});

var Table = React.createClass({
  render: function() {
  	return (
  	  <div>
  	    <h4 className="tableName">{this.props.data.name}</h4>
  	    <table className="table table-bordered table-striped">
  	      <thead>
  	        <tr>
  	          <th width="25%">Column Name</th>
  	          <th>SQLite Type</th>
  	          <th width="50%">Description</th>
  	        </tr>
          </thead>
          <tbody>
  	        {this.props.data.columns.map(function (column) {
  	          return <Column key={column.name} data={column} />
  	        })}
  	      </tbody>
  	    </table>
  	  </div>
  	);
  }
});

var Category = React.createClass({
  render: function() {
  	return (
  	  <div>
        <h3>{this.props.data.name}</h3>
  	    {this.props.data.tables.map(function (table) {
	   	    return <Table key={table.name} data={table} />
	   	  })}
      </div>
  	);
  }
});

var TagName = React.createClass({
  render: function() {
    var link = "/tables/" + this.props.tag + ".html";
    return (
      <span className="tagLink">
        <span className={this.props.className}>
          <InternalLink href={link}>{this.props.tag}</InternalLink>
        </span>
        <span> </span>
      </span>
    )
  }
})

var Page = React.createClass({
  render: function () {
    var tag = this.props.tag || 'master.html';
    var is_valid = false;

    // Make sure requested tag is valid.
    tag = tag.substring(0, tag.length - 5);
    for (var i = 0; i < Tags.length; i++) {
      if (tag == Tags[i]) {
        is_valid = true;
      }
    }

    if (!is_valid) {
      return (
        <NotFoundPage />
      );
    }

    var Master = require('../api/' + tag + '.js');
    
    return (
      <BasePage pageName="tables">
        <PageHeader
          title="Tables"
          subTitle="The osquery SQL tables and columns API." />

        <PageContainer>
          <p className="lead">
            <span><strong>Release Tags:</strong> </span>
            {Tags.map(function (tag_name) {
              var className = "label label-default";
              if (tag == tag_name) {
                className = "label label-primary";
              }
              return <TagName 
                key={tag_name}
                className={className}
                tag={tag_name}/>
            })}
          </p>
          <p className="lead">
          osquery exports the following set of tables organized by platform. 
          Treat them like SQLite tables:
          </p>
          <div className="highlight">
            <code>
              <span>SELECT </span>
              <span className="text-success">address</span>
              <span>, </span>
              <span className="text-success">mac</span>
              <span>, id.</span>
              <span className="text-success">interface</span>
              <br /> 
              <span>FROM </span>
              <span className="tableName">interface_details</span>
              <span> AS id, </span>
              <span className="tableName">interface_addresses</span>
              <span> AS ia WHERE id.</span>
              <span className="text-success">interface</span>
              <span> = ia.</span>
              <span className="text-success">interface</span>
              <span>;</span>
            </code>
          </div>
          
          <p className="lead">
          There are some operating-specific tables that apply to OS X, Ubuntu, 
          or CentOS only. osquery stresses feature parity, minimizing 
          tables that are not available to all platforms is a priority.
          </p>
          {Master.map(function (category) {
          	return <Category key={category.name} data={category} />
          })}
        </PageContainer>
      </BasePage>
    );
  }
});

module.exports = Page;

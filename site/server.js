/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant 
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

'use strict';

var express = require('express');

var development = process.env.NODE_ENV !== 'production';
var app = express();

if (development) {
  var path = require('path');
  var url = require('url');
  var browserify = require('connect-browserify');
  var nodejsx = require('node-jsx').install();
  var Root = require('./src/Root');

  app = app
    .get('/assets/bundle.js', browserify('./client', {debug: true, watch: false}))
    .use('/assets', express.static(path.join(__dirname, 'assets')))
    .use('/vendor', express.static(path.join(__dirname, 'vendor')))
    .use(function renderApp(req, res) {
      var fileName = url.parse(req.url).pathname;
      var RootHTML = Root.renderToString({initialPath: fileName});

      res.send(RootHTML);
    });
} else {
  app = app.use(express.static(__dirname));
}

app.listen(4000, function () {
  console.log('Server started at http://localhost:4000');
});

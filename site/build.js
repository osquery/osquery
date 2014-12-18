/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant 
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

var fs = require('fs');
var path = require('path');
var nodejsx = require('node-jsx').install();
var Root = require('./src/Root');

Root.getPages()
  .forEach(function (fileName) {
    var RootHTML = Root.renderToString({initialPath: fileName});
    process.stdout.write("Writing: " + fileName + '\n');

    var target = path.join(__dirname, fileName);
    var dirname = target.replace(/\\/g, '/').replace(/\/[^\/]*\/?$/, '');
    fs.exists(dirname, function(exists) {
      if (!exists) {
        fs.mkdirSync(dirname, 0755);
      }
      fs.writeFileSync(path.join(__dirname, fileName), RootHTML);
    });
  });

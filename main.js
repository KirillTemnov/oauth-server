
exports.version = '0.1.5';

exports.server = require('./lib/server');
exports.util = require('./lib/util');
exports.Consumer = require('./lib/data').Consumer;

var fs = require('fs');

// keys store middleware
exports.store = {};

fs.readdirSync(__dirname + '/lib/store').forEach(function(filename){
    if (/\.js$/.test(filename)) {
        var name = filename.substr(0, filename.lastIndexOf('.'));
        Object.defineProperty(exports.store, name, { get: function(){
            return require('./lib/store/' + name);
        }});
    }
});


//   Expose getters as first-class exports.
exports.__proto__ = exports.store;
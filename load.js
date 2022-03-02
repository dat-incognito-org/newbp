var ffi = require('ffi');
var ref = require('ref');
var Struct = require('ref-struct');

var myobj = Struct({
  'ptr': 'string',
  'len': ref.types.size_t,
  'cap': ref.types.size_t
});
var lib = ffi.Library('target/release/libnewbp', {
  'naive_prove': [myobj, [ref.types.void]]
});

let result = lib.naive_prove(null);
console.log("done!");
global.result = result;
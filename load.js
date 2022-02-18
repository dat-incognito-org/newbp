var ffi = require('ffi');

var lib = ffi.Library('target/release/libnewbp', {
  'naive_prove': ['void', []]
});

lib.naive_prove();

console.log("done!");
var ffi = require('ffi-napi');
var path = require('path');

var libm = ffi.Library(path.join(__dirname, '../tir-engine/target/release/libtirengine'), {
  'generate_knowledge': ['void', ['array']],
  //'double': ['string', ['int']],
});
console.log(JSON.stringify(libm))
let response = libm.double(2);
console.log(response);
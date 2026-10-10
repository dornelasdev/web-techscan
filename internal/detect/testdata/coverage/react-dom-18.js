// Authored ReactDOM 18.3.1-shaped marker scaffold, not a copied runtime.
var fixtureSuffix = Math.random().toString(36).slice(2);
var fixtureFiber = "__reactFiber$" + fixtureSuffix;
var fixtureProps = "__reactProps$" + fixtureSuffix;
var fixtureContainer = "__reactContainer$" + fixtureSuffix;
function fixtureError(code) {
  var url = "https://reactjs.org/docs/error-decoder.html?invariant=" + code;
  return "Minified React error #" + code + "; visit " + url;
}
var fixturePrivate = "private-runtime-body";

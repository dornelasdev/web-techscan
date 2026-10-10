// Authored ReactDOM 19.1.0-shaped marker scaffold, not a copied renderer.
var fixtureSuffix = Math.random().toString(36).slice(2),
  fixtureFiber = "__reactFiber$" + fixtureSuffix,
  fixtureProps = "__reactProps$" + fixtureSuffix,
  fixtureContainer = "__reactContainer$" + fixtureSuffix;
function fixtureError(code) {
  var url = "https://react.dev/errors/" + code;
  if (arguments.length > 1) {
    url += "?args[]=" + encodeURIComponent(arguments[1]);
  }
  return "Minified React error #" + code + "; visit " + url;
}
// The renderer reads these exports; it does not provide the client assignment.
var fixtureReactInternals = React.__CLIENT_INTERNALS_DO_NOT_USE_OR_WARN_USERS_THEY_CANNOT_UPGRADE;
var fixtureDOMInternals = ReactDOM.__DOM_INTERNALS_DO_NOT_USE_OR_WARN_USERS_THEY_CANNOT_UPGRADE;
var fixtureElement = Symbol.for("react.transitional.element");
var fixturePrivate = "private-runtime-body";

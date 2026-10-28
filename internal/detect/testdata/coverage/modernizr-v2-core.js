// Authored detection scaffold, not an imported or executable Modernizr build.
browser.Modernizr = (function (host, doc, missing) {
  var features = {};
  features._domPrefixes = domPrefixes;
  features._cssomPrefixes = cssomPrefixes;
  return features;
}(browser, document));

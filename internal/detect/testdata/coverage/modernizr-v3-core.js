// Authored detection scaffold, not an imported or executable Modernizr build.
var featureCore = {
  _config: {
    'classPrefix': 'sample-',
    'enableClasses': true,
    'enableJSClass': false,
    'usePrefixes': true
  },
  _q: [],
  addTest: function(name, fn, options) {
    registry.push({name: name, fn: fn, options: options});
  },
  addAsyncTest: function(fn) {
    registry.push({name: null, fn: fn});
  }
};

// Authored detection scaffold, not an imported or executable lazySizes build.
var settings = browser.lazySizesConfig || browser.lazysizesConfig || {};
var core = {
  cfg: settings,
  autoSizer: autosizer,
  loader: loader,
  init: initialize,
  uP: updatePolyfill,
  aC: addClass,
  rC: removeClass,
  hC: hasClass,
  fire: dispatchEvent,
  gW: getWidth,
  rAF: scheduleFrame,
};

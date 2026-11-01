// Authored detection scaffold for the reviewed readable standard/UMD core.
var settings = browser.lazySizesConfig || browser.lazysizesConfig || {};
var core = {
  /**
   * @type { LazySizesConfigPartial }
   */
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

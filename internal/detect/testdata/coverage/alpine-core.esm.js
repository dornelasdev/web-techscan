// Authored ESM-shaped scaffold; imports and JavaScript execution are not inspected.
function begin() {
  dispatch(document, 'alpine:init');
  dispatch(document, 'alpine:initializing');
}
var core = {
  flushAndStopDeferringMutations,
  dontAutoEvaluateFunctions,
  disableEffectScheduling,
  startObservingMutations,
  stopObservingMutations,
  setReactivityEngine,
};
export default core;

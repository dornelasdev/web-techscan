// Authored Alpine 3.x marker scaffold; not an upstream runtime or executable example.
function begin() {
  dispatch(document, "alpine:init");
  dispatch(document, "alpine:initializing");
}
var core = {
  flushAndStopDeferringMutations,
  dontAutoEvaluateFunctions,
  disableEffectScheduling,
  startObservingMutations,
  stopObservingMutations,
  setReactivityEngine,
};

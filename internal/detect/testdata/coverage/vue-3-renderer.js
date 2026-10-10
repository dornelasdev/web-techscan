// Authored Vue 3.5.13-shaped marker scaffold, not a copied runtime.
const fragment = Symbol.for('v-fgt');
const target = globalThis;
function createRenderer() {
  target.__VUE__ = true;
}
function mount(container, app) {
  container.__vue_app__ = app;
}
const fixture = 'private-vue-body';
export { createRenderer, mount, fragment, fixture };

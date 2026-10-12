// Authored Angular-shaped marker scaffold; not an imported runtime.
function attachContext(target, view) {
    target[contextKey] = view;
}
const contextKey = '__ngContext__';
function defineComponent(metadata) {
    return metadata;
}
function FixtureComponent() {}
FixtureComponent.ɵcmp = defineComponent({type: FixtureComponent});
const hostAttributes = ['ng-version', '20.3.0'];
const fixtureContent = 'private-angular-body';

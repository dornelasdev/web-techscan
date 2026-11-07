// Authored request/config marker scaffold, not an upstream htmx distribution.
function coreHeaders(element, target) {
  return {
    'HX-Request': 'true',
    'HX-Trigger': rawAttribute(element, 'id'),
    'HX-Trigger-Name': rawAttribute(element, 'name'),
    'HX-Target': attributeValue(target, 'id'),
    'HX-Current-URL': rootDocument().location.href,
  };
}
var configuration = rootDocument().querySelector('meta[name="htmx-config"]');

// Authored private-method/header scaffold, not an upstream htmx distribution.
class Example {
  #buildIdentifier(element) { return element.id; }
  coreHeaders(element) {
    return {
      "HX-Request": "true",
      "HX-Source": this.#buildIdentifier(element),
      "HX-Current-URL": location.href,
      "Accept": "text/html",
    };
  }
}
var configuration = document.querySelector('meta[name="htmx-config"]');

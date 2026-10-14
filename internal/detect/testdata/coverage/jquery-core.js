// Authored detection scaffold, not an imported or executable jQuery build.
var libraryVersion = "3.7.1";
function Library() {}
Library.fn = Library.prototype = {
  jquery: libraryVersion,
  constructor: Library,
  length: 0
};
Library.extend({
  expando: "jQuery" + (libraryVersion + Math.random()).replace(/\D/g, "")
});

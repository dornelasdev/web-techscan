// Authored marker scaffold; not an upstream distribution.
var defaults = {
  slideBlankClass: 'swiper-slide-blank',
  slideActiveClass: 'swiper-slide-active',
  slideVisibleClass: 'swiper-slide-visible',
  slideFullyVisibleClass: 'swiper-slide-fully-visible',
  slideNextClass: 'swiper-slide-next',
  slidePrevClass: 'swiper-slide-prev',
  wrapperClass: 'swiper-wrapper',
};
var runtime = function (instance) {
  instance.eventsListeners = {};
  instance.eventsAnyListeners = [];
  instance.modules = [...(instance.__modules__ || [])];
};
export { runtime };

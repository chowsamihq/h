'use strict';

var Controller = require('../base/controller');

class LozengeController extends Controller {
  constructor(el, opts) {
    super(el, opts);
    var lozengeEl = document.createElement('div');
    lozengeEl.innerHTML =
      '<div class="js-lozenge-content lozenge-content">'+
      opts.content+
      '</div>' +
      '<div class="js-lozenge-close lozenge-close">x</div>';
    lozengeEl.classList.add('lozenge');
    lozengeEl.classList.add('js-lozenge');
    el.appendChild(lozengeEl);

    lozengeEl.querySelector('.js-lozenge-close').addEventListener('mousedown', () => {
      lozengeEl.remove();
      opts.deleteFn();
    });
  };
};

module.exports = LozengeController;

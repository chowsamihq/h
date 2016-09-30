'use strict';

var Controller = require('../base/controller');
var setElementState = require('../util/dom').setElementState;
var LozengeController = require('./lozenge-controller');
var SearchTextParser = require('../util/search-text-parser');

/**
 * Controller for the search bar.
 */
class SearchBarController extends Controller {
  constructor(element) {
    super(element);

    this._dropdown = this.refs.searchBarDropdown;
    this._dropdownItems = Array.from(
      element.querySelectorAll('[data-ref="searchBarDropdownItem"]'));
    this._input = this.refs.searchBarInput;
    this._inputHidden = this.refs.searchBarInputHidden;
    this._lozenges = this.refs.searchBarLozenges;
    this._queryParam = '';

    var getActiveDropdownItem = () => {
      return element.querySelector('.js-search-bar-dropdown-menu-item--active');
    };

    var clearActiveDropdownItem = () => {
      var activeItem = getActiveDropdownItem();
      if (activeItem) {
        activeItem.classList.remove('js-search-bar-dropdown-menu-item--active');
      }
    };

    var updateActiveDropdownItem = element => {
      clearActiveDropdownItem();
      element.classList.add('js-search-bar-dropdown-menu-item--active');
    };

    var selectFacet = facet => {
      this._input.value = facet;

      closeDropdown();

      setTimeout(function() {
        this._input.focus();
      }.bind(this), 0);
    };

    var isHidden = element => {
      return element &&
        (element.nodeType !== 1 ||
          !element.classList ||
          element.classList.contains('is-hidden'));
    };

    var getPreviousVisibleSiblingElement = element => {
      if (!element) {
        return null;
      }

      do {
        element = element.previousSibling;
      } while (isHidden(element));
      return element;
    };

    var getNextVisibleSiblingElement = element => {
      if (!element) {
        return null;
      }

      do {
        element = element.nextSibling;
      } while (isHidden(element));

      return element;
    };

    var showAllDropdownItems = () => {
      this._dropdownItems.forEach(function(dropdownItem) {
        dropdownItem.classList.remove('is-hidden');
      });
    };

    var closeDropdown = () => {
      if (!this.state.open) { return; }
      clearActiveDropdownItem();
      showAllDropdownItems();
      this.setState({open: false});
      this._input.removeEventListener('keydown', setupDropdownListenerKeys);
    };

    var openDropdown = () => {
      if (this.state.open) { return; }
      clearActiveDropdownItem();
      this.setState({open: true});
      this._input.addEventListener('keydown', setupDropdownListenerKeys);
    };

    var getVisibleDropdownItems = () => {
      return this._dropdown.querySelectorAll('li:not(.is-hidden)');
    };

    /** Show items that match the word and hide ones that don't. */
    var setVisibleDropdownItems = word => {
      this._dropdownItems.forEach(function(dropdownItem) {
        var dropdownItemTitle =
          dropdownItem.querySelector('[data-ref="searchBarDropdownItemTitle"]').
            innerHTML.trim();
        if (dropdownItemTitle.indexOf(word) < 0) {
          dropdownItem.classList.add('is-hidden');
        } else {
          dropdownItem.classList.remove('is-hidden');
        }
      });
    };

    var getTrimmedInputValue = () => {
      return this._input.value.trim();
    };

    var maybeOpenOrCloseDropdown = () => {
      var word = getTrimmedInputValue();
      var shouldOpenDropdown = true;

      // If there are no visible items that match the word close the dropdown
      if (getVisibleDropdownItems().length < 1) {
        shouldOpenDropdown = false;
      }

      // If the word has a ':' don't show dropdown
      if (word.indexOf(':') > -1) {
        shouldOpenDropdown = false;
      }

      if (shouldOpenDropdown) {
        openDropdown();
      } else {
        closeDropdown();
      }
    };

    var lozengify = content => {
      var deleteFn = () => {
        var queryTerms = SearchTextParser.getQueryTerms(this._inputHidden.value);
        queryTerms = queryTerms.map(function(term) {
          if (term !== content) {
            return term;
          }
        });
        this._inputHidden.value = queryTerms.join(' ');
        this.element.querySelector('form').submit();
      };

      new LozengeController(
        this._lozenges,
        {
          content: content,
          deleteFn: deleteFn,
        },
      );

      //clear input
      this._input.value = '';

      // add to state
      this.setState({newQueryParam: content});
    };

    var lozengifyQueryParams = () => {
      var queryTerms = SearchTextParser.getQueryTerms(this._inputHidden.value);
      queryTerms.forEach(function(term) {
        lozengify(term);
      });
    };

    var updateQueryParam = () => {
      this._inputHidden.value = this._queryParam + ' ' + getTrimmedInputValue();
    };

    var setupListenerKeys = (event, handlers) => {
      var handler = handlers[event.keyCode];
      if (handler) {
        handler(event);
      }
    };

    var setupLozengeListenerKeys = event => {
      const SPACE_KEY_CODE = 32;

      var handleSpaceKey = () => {
        var word = getTrimmedInputValue();
        if (SearchTextParser.shouldLozengify(word)) {
          lozengify(word);
        }
      };

      var handlers = {};
      handlers[SPACE_KEY_CODE] = handleSpaceKey;
      setupListenerKeys(event, handlers);
    };

    var setupDropdownListenerKeys = event => {
      const DOWN_ARROW_KEY_CODE = 40;
      const ENTER_KEY_CODE = 13;
      const UP_ARROW_KEY_CODE = 38;

      var activeItem = getActiveDropdownItem();
      var handlers = {};

      var visibleDropdownItems = getVisibleDropdownItems();

      var handleDownArrowKey = () => {
        updateActiveDropdownItem(getNextVisibleSiblingElement(activeItem) ||
          visibleDropdownItems[0]);
      };

      var handleEnterKey = event => {
        if (activeItem) {
          event.preventDefault();
          var facet =
            activeItem.
              querySelector('[data-ref="searchBarDropdownItemTitle"]').
              innerHTML.trim();
          selectFacet(facet);
        } else {
          updateQueryParam();
          this.element.querySelector('form').submit();
        }
      };

      var handleUpArrowKey = () => {
        updateActiveDropdownItem(getPreviousVisibleSiblingElement(activeItem) ||
          visibleDropdownItems[visibleDropdownItems.length - 1]);
      };

      handlers[DOWN_ARROW_KEY_CODE] = handleDownArrowKey;
      handlers[ENTER_KEY_CODE] = handleEnterKey;
      handlers[UP_ARROW_KEY_CODE] = handleUpArrowKey;

      setupListenerKeys(event, handlers);
    };

    var handleClickOnItem = event => {
      var facet =
        event.currentTarget.
          querySelector('[data-ref="searchBarDropdownItemTitle"]').
          innerHTML.trim();
      selectFacet(facet);
    };

    var handleHoverOnItem = event => {
      updateActiveDropdownItem(event.currentTarget);
    };

    var handleClickOnDropdown = event => {
      // prevent clicking on a part of the dropdown menu itself that
      // isn't one of the suggestions from closing the menu
      event.preventDefault();
    };

    var handleFocusOutside = event => {
      if (!element.contains(event.target) ||
        !element.contains(event.relatedTarget)) {
        this.setState({open: false});
      }
      closeDropdown();
      this._input.removeEventListener('keydown', setupDropdownListenerKeys,
        true /*capture*/);
      this._input.removeEventListener('keydown', setupLozengeListenerKeys,
        true /*capture*/);
    };

    var handleFocusinOnInput = () => {
      maybeOpenOrCloseDropdown();
    };

    var handleInputOnInput = event => {
      var word = getTrimmedInputValue();
      setVisibleDropdownItems(word);
      maybeOpenOrCloseDropdown();
      this._input.addEventListener('keydown', setupLozengeListenerKeys);
    };

    this._dropdownItems.forEach(function(item) {
      if(item && item.addEventListener) {
        item.addEventListener('mousemove', handleHoverOnItem);
        item.addEventListener('mousedown', handleClickOnItem);
      }
    });

    this._dropdown.addEventListener('mousedown', handleClickOnDropdown);
    this._input.addEventListener('blur', handleFocusOutside);
    this._input.addEventListener('input', handleInputOnInput);
    this._input.addEventListener('focus', handleFocusinOnInput);

    lozengifyQueryParams();
  }

  update(state) {
    setElementState(this._dropdown, {open: state.open});
    if (state.newQueryParam) {
      this._queryParam = this._queryParam  + ' ' + state.newQueryParam;
      this.setState({newQueryParam : null});
    }
  }
}

module.exports = SearchBarController;

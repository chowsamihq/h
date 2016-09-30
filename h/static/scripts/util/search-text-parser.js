'use strict';

function canLozengify(phrase) {
  phrase = phrase.trim();
  // if there is no word
  if (!phrase) {
    return false;
  }
  // if phrase starts with a double quote, it has to end with one
  if (phrase.indexOf('"') === 0 && phrase.indexOf('"', 1) !== phrase.length - 1) {
    return false;
  }
  // if phrase ends with a double quote it has to start with one
  if (phrase.indexOf('"', 1) === phrase.length - 1 && phrase.indexOf('"') !== 0) {
    return false;
  }
  // if phrase starts with a single quote, it has to end with one
  if (phrase.indexOf("'") === 0 && phrase.indexOf("'", 1) !== phrase.length - 1) {
    return false;
  }
  // if phrase ends with a single quote it has to start with one
  if (phrase.indexOf("'", 1) === phrase.length - 1 && phrase.indexOf("'") !== 0) {
    return false;
  }
  return true;
}

function shouldLozengify(phrase) {
  var facetName;
  var facetValue;
  var i;

  // if the phrase has a facet and value
  if (phrase.indexOf(':') >= 0) {
    i = phrase.indexOf(':');
    facetName = phrase.slice(0, i).trim();
    facetValue = phrase.slice(i+1, phrase.length).trim();

    if (!canLozengify(facetName)) {
      return false;
    }

    if (facetValue.length > 0 && !canLozengify(facetValue)) {
      return false;
    }
  } else {
    if (!canLozengify(phrase)) {
      return false;
    }
  }
  return true;
}

function getQueryTerms(queryString) {
  var inputTerms = '';
  var quoted;
  var queryTerms = [];
  queryString.split(' ').forEach(function(term) {
    if (quoted) {
      inputTerms = inputTerms + ' ' + term;
      if (shouldLozengify(inputTerms)) {
        queryTerms.push(inputTerms);
        inputTerms = '';
        quoted = false;
      }
    } else {
      if (shouldLozengify(term)) {
        queryTerms.push(term);
      } else {
        inputTerms = term;
        quoted = true;
      }
    }
  });
  if(inputTerms) {
    queryTerms.push(inputTerms);
  }
  return queryTerms;
}

module.exports = {
  shouldLozengify: shouldLozengify,
  getQueryTerms: getQueryTerms,
};

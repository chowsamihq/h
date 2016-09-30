'use strict';

var searchTextParser = require('../../util/search-text-parser');
var unroll = require('../util').unroll;

describe('SearchTextParser', function () {
  unroll('should create a lozenge', function (done, fixture) {
    assert.isTrue(searchTextParser.shouldLozengify(fixture.input));
    done();
  },[
    {input: 'foo'},
    {input: '    foo    '},
    {input: '"foo bar"'},
    {input: '\'foo bar\''},
    {input: 'foo:"bar"'},
    {input: 'foo:\'bar\''},
    {input: 'foo:\'bar1 bar2\''},
    {input: 'foo:"bar1 bar2"'},
    {input: 'foo:'},
    {input: '\'foo\':'},
    {input: '"foo":'},
    {input: 'foo"bar:'},
    {input: 'foo\'bar:'},
  ]);

  unroll('should not create a lozenge for', function (done, fixture) {
    assert.isFalse(searchTextParser.shouldLozengify(fixture.input));
    done();
  },[
    {input: 'foo\''},
    {input: 'foo\"'},
    {input: '\'foo'},
    {input: '\"foo'},
    {input: ''},
    {input: 'foo:\'bar'},
    {input: 'foo:\"bar'},
  ]);
});

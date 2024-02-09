'use strict';

const { test } = require('tap');
const localCache = require('../../lib/local-cache');

test('build key', async ({ equal }) => {
  const composedKey = 'a:b:c';
  const cache = localCache();
  equal(cache.buildKey('a', 'b', 'c'), composedKey);
});

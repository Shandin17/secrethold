'use strict';

const { test } = require('tap');
const metautil = require('../../lib/error');

test('error', (t) => {
  const e1 = new metautil.Error('Custom error', 1001);
  t.type(e1.stack, 'string');
  t.ok(e1 instanceof Error);
  t.ok(e1 instanceof metautil.Error);
  t.equal(e1.message, 'Custom error');
  t.equal(e1.code, 1001);
  t.equal(e1.cause, undefined);

  const e2 = new metautil.Error('Ups', { code: 1001, cause: e1 });
  t.equal(e2.code, 1001);
  t.equal(e2.cause, e1);

  const e3 = new metautil.Error('Something went wrong');
  t.equal(e3.code, undefined);
  t.equal(e3.cause, undefined);

  const e4 = new metautil.Error('Something went wrong', 'ERRCODE');
  t.equal(e4.code, 'ERRCODE');

  t.end();
});

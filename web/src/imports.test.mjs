import test from 'node:test';
import assert from 'node:assert/strict';
import {parseIndicators} from './imports.mjs';

test('IOC import supports arrays and indicator wrappers', () => {
  assert.deepEqual(parseIndicators('[{"type":"ip"}]'), [{type:'ip'}]);
  assert.deepEqual(parseIndicators('{"indicators":[]}'), []);
});
test('malformed IOC structures never reach React state', () => {
  for (const input of ['{}', 'null', '{"indicators":null}', '[null]', '[[]]', '[1]', '"text"']) {
    assert.throws(() => parseIndicators(input), /IOC/);
  }
});
test('invalid JSON is a recoverable import error', () => {
  assert.throws(() => parseIndicators('{'), SyntaxError);
});

// Verify the shipped ledger using exactly the algorithm the demo page runs.
//
// The page claims a visitor's browser independently recomputes the hashes. This
// re-implements that walk outside the browser so the claim is tested in CI
// rather than eyeballed once. If this passes, a browser running the same code
// over the same bytes reaches the same answer.
'use strict';
const fs = require('fs');
const crypto = require('crypto');
const { canonicalBody } = require('./canon_check.js');

const GENESIS = '0'.repeat(64);

function sha256(str) {
  return crypto.createHash('sha256').update(str, 'utf8').digest('hex');
}

function verifyChain(records) {
  let prev = GENESIS;
  for (let i = 0; i < records.length; i++) {
    const r = records[i];
    if (r.prev_hash !== prev) {
      return { ok: false, index: i, id: r.record_id, reason: 'prev_hash mismatch' };
    }
    if (sha256(prev + canonicalBody(r)) !== r.hash) {
      return { ok: false, index: i, id: r.record_id, reason: 'contents do not match hash' };
    }
    prev = r.hash;
  }
  return { ok: true, count: records.length };
}

const bundle = JSON.parse(fs.readFileSync(process.argv[2] || 'demo/ledger.json', 'utf8'));
const clean = verifyChain(bundle.records);

let failures = 0;
function check(name, cond, detail) {
  if (cond) { console.log('PASS ' + name); }
  else { failures++; console.log('FAIL ' + name + (detail ? ': ' + detail : '')); }
}

check('the shipped ledger verifies under the page algorithm',
      clean.ok, JSON.stringify(clean));
check('every record was checked', clean.count === bundle.records.length);

// The tamper the page's button performs: turn the rejection of a fabricated
// income figure into a pass, so the file reads as though the model was right.
const tampered = JSON.parse(JSON.stringify(bundle.records));
tampered[1].response_treatment = 'pass';
tampered[1].disposition = 'committed';
tampered[1].findings = [];
const broken = verifyChain(tampered);
check('the page\'s tamper is detected', !broken.ok);
check('it is blamed on the record that was actually edited',
      broken.index === 1, 'blamed ' + broken.index);

// Deleting a record must not go unnoticed either.
const shortened = JSON.parse(JSON.stringify(bundle.records));
shortened.splice(2, 1);
check('a deleted record is detected', !verifyChain(shortened).ok);

// A record moved to a different position breaks continuity.
const shuffled = JSON.parse(JSON.stringify(bundle.records));
[shuffled[3], shuffled[4]] = [shuffled[4], shuffled[3]];
check('a reordered chain is detected', !verifyChain(shuffled).ok);

console.log('\n' + failures + ' failure(s)');
process.exit(failures ? 1 : 0);

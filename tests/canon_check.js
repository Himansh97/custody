// The browser-side canonicaliser, isolated so it can be diffed against Python's.
//
// The demo's entire claim is that a visitor's browser independently recomputes
// the hashes. That is only true if this file and `custody/chain.py` agree on the
// exact bytes, so the agreement is tested rather than asserted.
'use strict';
const fs = require('fs');

const CHAIN_FIELDS = new Set(['prev_hash', 'hash', 'signature']);

// Built from an ASCII string rather than a literal so the source file itself
// stays free of the control characters it is describing.
const NON_ASCII = new RegExp('[\\u0080-\\uFFFF]', 'g');

function canon(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  return '{' + Object.keys(v).sort()
    .map(k => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
}

// Python writes ensure_ascii=True; JSON.stringify leaves non-ASCII raw.
function escapeNonAscii(s) {
  return s.replace(NON_ASCII,
    c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'));
}

function canonicalBody(record) {
  const body = {};
  for (const k of Object.keys(record)) if (!CHAIN_FIELDS.has(k)) body[k] = record[k];
  return escapeNonAscii(canon(body));
}

if (require.main === module) {
  const bundle = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
  console.log(JSON.stringify(bundle.records.map(canonicalBody)));
}

module.exports = { canonicalBody };

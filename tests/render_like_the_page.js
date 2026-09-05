// Run the demo page's own rendering code outside a browser.
//
// `verify_like_the_page.js` covers the hashing. This covers the rest: the loan
// selector, the disclosure panels and the usage table. Those went in because a
// real lender's ledger holds many loans and the disclosure report is the thing
// an examiner is actually handed -- neither of which the single-loan demo
// exercises, so neither would be caught breaking by looking at the demo.
//
// The DOM here is a stub, not a browser. It is enough to prove the code paths
// run, populate the right nodes, and filter on the right key; it proves nothing
// about layout.
'use strict';
const fs = require('fs');
const path = require('path');
const vm = require('vm');

// ------------------------------------------------------------------- the stub

class El {
  constructor(tag) {
    this.tag = tag;
    this.children = [];
    this.attrs = {};
    this.listeners = {};
    this._html = '';
    this.textContent = '';
    this.className = '';
    this.hidden = false;
    this.disabled = false;
  }
  set innerHTML(v) {
    this._html = v;
    // Enough parsing for what the page builds: a flat list of elements whose
    // text is filled in afterwards by querySelector.
    this.children = [];
    const tags = v.match(/<(div|tr|td|th|thead|tbody)\b[^>]*>/g) || [];
    for (const t of tags) {
      const m = /<(\w+)[^>]*class="([^"]*)"/.exec(t);
      const el = new El(RegExp.$1 || 'div');
      if (m) el.className = m[2];
      this.children.push(el);
    }
  }
  get innerHTML() { return this._html; }
  appendChild(c) { this.children.push(c); return c; }
  addEventListener(name, fn) { (this.listeners[name] ||= []).push(fn); }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  getAttribute(k) { return this.attrs[k]; }
  click() { (this.listeners.click || []).forEach((f) => f()); }
  querySelector(sel) {
    const want = sel.replace(/^\./, '');
    return this.children.find(
      (c) => c.tag === sel || c.className.split(' ').includes(want)) || new El('div');
  }
  querySelectorAll(sel) {
    const want = sel.replace(/^\./, '').replace(/^td\./, '');
    return this.children.filter(
      (c) => c.tag === sel || c.className.split(' ').includes(want));
  }
}

function run(bundle, opts = {}) {
  const posted = [];
  const page = fs.readFileSync(
    path.join(__dirname, '..', 'src', 'custody', 'page.html'), 'utf8');
  const script = /<script>\n([\s\S]*?)<\/script>/.exec(page)[1];

  const nodes = new Map();
  const document = {
    getElementById(id) {
      if (!nodes.has(id)) {
        const el = new El('div');
        el.textContent = id === 'ledger-data' ? JSON.stringify(bundle) : '';
        nodes.set(id, el);
      }
      return nodes.get(id);
    },
    createElement: (tag) => new El(tag),
    body: new El('body'),
    documentElement: Object.assign(new El('html'), { scrollHeight: 800 }),
  };

  const sandbox = {
    document,
    // The page reads these only in embed mode; supplied so the branch is
    // exercised rather than skipped.
    location: { search: opts.embed ? '?embed=1' : '' },
    parent: { postMessage(msg) { posted.push(msg); } },
    ResizeObserver: class { observe() {} },
    TextEncoder,
    crypto: require('crypto').webcrypto,
    console,
    JSON, Object, Array, String, Number, Boolean, Math, RegExp, Date, Promise,
    parseInt, parseFloat, isNaN,
  };
  sandbox.window = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(script, sandbox, { timeout: 5000 });
  nodes.set('__posted', posted);
  nodes.set('__body', document.body);
  return nodes;
}

// -------------------------------------------------------------------- checks

let failures = 0;
function check(name, cond, detail) {
  if (cond) { console.log(`PASS ${name}`); }
  else { failures++; console.log(`FAIL ${name}${detail ? ': ' + detail : ''}`); }
}

const single = JSON.parse(fs.readFileSync(
  path.join(__dirname, '..', 'demo', 'ledger.json'), 'utf8'));

// A ledger with several loans, built by widening the shipped one. The records
// keep their real hashes; only which loan they name changes, which is all the
// selector and the packet index look at.
const many = JSON.parse(JSON.stringify(single));
const extraLoans = ['1000255', '1000256', '1000257'];
many.records.forEach((r, i) => { if (i % 2 === 1) r.loan = extraLoans[i % 3]; });
many.packets = {};
for (const loan of ['1000254', ...extraLoans]) {
  many.packets[loan] = {
    loan,
    summary: { ai_decisions: 1, human_reviews: 0, committed: 1, rejected: 0,
               routed_to_human: 0, denied_by_policy: 0, overrides: 0,
               models_used: ['claude-sonnet-5'] },
    mandate_coverage: { complete: true },
    records: many.records.filter((r) => r.loan === loan),
  };
}

// ---- one loan: the selector stays out of the way -------------------------
let n = run(single);
check('a single-loan ledger hides the loan selector',
      n.get('loans').hidden === true);
check('the disclosure names every model that answered',
      n.get('dModels').children.length === single.disclosure.models.length,
      `${n.get('dModels').children.length} rows for ` +
      `${single.disclosure.models.length} models`);
check('the usage table has a row per purpose',
      n.get('dPurposes').querySelectorAll('p').length ===
        single.disclosure.purposes.length);
check('the safeguards panel is populated',
      n.get('dSafeguards').children.length > 0);
check('the limits are shown rather than dropped',
      n.get('discloseLimits').textContent.includes('cannot inventory models'));
check('a purpose name is rendered as text, not markup',
      n.get('dPurposes').querySelectorAll('p')[0].textContent.length > 0);

// ---- embed mode: the same page, without its own framing ------------------
const embedded = run(single, { embed: true });
check('embed mode marks the body so the masthead and footer drop out',
      embedded.get('__body').className.includes('embed'),
      `class was "${embedded.get('__body').className}"`);
check('embed mode reports its height to the host',
      embedded.get('__posted').some((m) => typeof m.custodyHeight === 'number'));
check('the normal page is not in embed mode',
      !run(single).get('__body').className.includes('embed'));

// ---- many loans: the selector appears and filters -------------------------
n = run(many);
const pills = n.get('loanPills').children;
check('a multi-loan ledger shows the loan selector',
      n.get('loans').hidden === false);
check('there is a pill per loan plus "All loans"',
      pills.length === 5, `${pills.length} pills for 4 loans`);
check('"All loans" is selected first',
      pills[0].getAttribute('aria-selected') === 'true');

const before = n.get('chain').children.length;
check('every record is listed before filtering',
      before === many.records.length, `${before} of ${many.records.length}`);

pills[2].click();
const after = n.get('chain').children.length;
const expected = many.records.filter((r) => r.loan === pills[2].textContent).length;
check('choosing a loan filters the chain to that loan',
      after === expected && after < before,
      `${after} rows, expected ${expected}, unfiltered was ${before}`);

n.get('loanPills').children[0].click();
check('choosing "All loans" restores the full chain',
      n.get('chain').children.length === many.records.length);

console.log(`\n${failures} failure(s)`);
process.exit(failures ? 1 : 0);

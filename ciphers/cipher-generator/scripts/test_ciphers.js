// Node-based self-test for js/ciphers.js: round-trips every cipher and checks
// a handful of known reference vectors (ACA Quagmire I-IV examples, Kryptos
// K1/K2 via Quagmire III, and a few textbook vectors for other ciphers).
'use strict';
const fs = require('fs');
const path = require('path');

global.window = global; // ciphers.js and the data files attach to `window`

function load(relPath) {
  const code = fs.readFileSync(path.join(__dirname, '..', relPath), 'utf8');
  // eslint-disable-next-line no-eval
  (0, eval)(code);
}

load('js/data/dictionary_data.js');
load('js/data/corpora_data.js');
load('js/ciphers.js');
load('js/generator.js');

const { CIPHERS, onlyLetters } = global.CipherLib;

let failures = 0;
let checks = 0;

function assertEq(actual, expected, label) {
  checks++;
  if (actual !== expected) {
    failures++;
    console.log(`FAIL: ${label}\n  expected: ${expected}\n  actual:   ${actual}`);
  }
}

function assertTrue(cond, label) {
  checks++;
  if (!cond) { failures++; console.log(`FAIL: ${label}`); }
}

// A handful of checks below (generateBulkAsync across more than one cipher
// type) genuinely span multiple event-loop turns - it deliberately
// `setTimeout`s between cipher types so a real browser tab stays
// responsive during a long bulk run. Everything else in this file runs
// fully synchronously; these are queued here and drained (one at a time,
// waiting for each `done()`) right before the final tally/exit at the
// bottom of the file, instead of forcing the async parts to fit into the
// synchronous flow above.
const asyncTests = [];
function asyncTest(fn) { asyncTests.push(fn); }
function runAsyncTests(tests, cb) {
  let i = 0;
  function next() {
    if (i >= tests.length) { cb(); return; }
    tests[i++](next);
  }
  next();
}

// ---------------------------------------------------------------------
// 1. Round-trip every cipher with a random key, several times, on random
//    plaintext lengths.
// ---------------------------------------------------------------------
const SAMPLE_PLAINTEXTS = [
  'THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG',
  'BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION',
  'PACKMYBOXWITHFIVEDOZENLIQUORJUGS',
  'ATTACKATDAWNFROMTHENORTHWITHALLAVAILABLEFORCES',
];

for (const id of Object.keys(CIPHERS)) {
  const def = CIPHERS[id];
  for (const pt of SAMPLE_PLAINTEXTS) {
    for (let trial = 0; trial < 3; trial++) {
      let key, values;
      try {
        const rk = def.randomKey({ ptLength: pt.length });
        key = rk.key; values = rk.values;
      } catch (e) {
        failures++; console.log(`FAIL: ${id} randomKey threw: ${e.message}`); continue;
      }
      let ct, pt2;
      try {
        ct = def.encrypt(pt, key);
        pt2 = def.decrypt(ct, key);
      } catch (e) {
        failures++; console.log(`FAIL: ${id} encrypt/decrypt threw: ${e.message}\n  key=${JSON.stringify(key)}`); continue;
      }
      checks++;
      // Hill/Playfair may pad with X/Q and merge I/J; allow those specific,
      // well-understood divergences instead of exact equality.
      let expected = pt;
      if (id === 'hill') { expected = pt; while (expected.length % key.size !== 0) expected += 'X'; }
      if (id === 'playfair' || id === 'adfgx' || id === 'bifid') expected = pt.replace(/J/g, 'I');
      let ok = pt2 === expected;
      if (id === 'homophonic_substitution') ok = true; // checked separately below via decrypt(ct)
      if (id === 'playfair') {
        // Playfair may also insert filler letters for doubled letters within a
        // pair, so just check the recovered text still starts with the
        // original letters at the right positions is too strict; instead
        // verify by re-encrypting.
        ok = def.encrypt(pt2, key) === ct;
      }
      if (!ok) {
        failures++;
        console.log(`FAIL round-trip: ${id}\n  pt : ${pt}\n  key: ${JSON.stringify(values)}\n  ct : ${ct}\n  pt2: ${pt2}`);
      }
      // Also verify keyFromValues(values) reproduces a working key (manual-mode path)
      if (def.keyFromValues) {
        try {
          const key2 = def.keyFromValues(values);
          checks++;
          if (id === 'homophonic_substitution') {
            // homophonic ciphertext varies call to call (multiple valid codes
            // per letter); check the *mapping* reproduces instead of exact ct.
            if (def.decrypt(ct, key2) !== pt) { failures++; console.log(`FAIL keyFromValues mismatch: ${id} (mapping not reproduced)`); }
          } else {
            const ct2 = def.encrypt(pt, key2);
            if (ct2 !== ct) { failures++; console.log(`FAIL keyFromValues mismatch: ${id}\n  ct:  ${ct}\n  ct2: ${ct2}`); }
          }
        } catch (e) {
          failures++; console.log(`FAIL: ${id} keyFromValues threw: ${e.message} values=${JSON.stringify(values)}`);
        }
      }
    }
  }
}

console.log(`\nRound-trip + keyFromValues checks done. ${checks} checks, ${failures} failures so far.\n`);

// ---------------------------------------------------------------------
// 2. Known reference vectors
// ---------------------------------------------------------------------

// --- Quagmire I (ACA reference) ---
{
  const key = { keyword1: 'SPRINGFEVER', indicator: 'FLOWER' };
  const pt = 'THEQUAGONEISAPERIODICCIPHERWITHAKEYEDPLAINALPHABETRUNAGAINSTASTRAIGHTCIPHERALPHABET';
  const expectedCt = 'QPMGQRBUJUYIFDMPYAIFQYYJJJHJYCJLUUTPIDVWYMFSGAESDWHIZRBLIRVCFCZPELBPZYYJJJHWLJJLPUP';
  const ct = CIPHERS.quagmire1.encrypt(pt, key);
  assertEq(ct, expectedCt, 'Quagmire I (ACA reference)');
  assertEq(CIPHERS.quagmire1.decrypt(ct, key), pt, 'Quagmire I decrypt round-trip');
}

// --- Quagmire II (ACA reference) ---
{
  const key = { keyword1: 'SPRINGFEVER', indicator: 'FLOWER' };
  const pt = 'INTHEQUAGTWOASTRAIGHTPLAINALPHABETISRUNAGAINSTAKEYEDCIPHERALPHABET';
  const expectedCt = 'JICICOSLYKILFVCHEBDXCCORJIOEWAFMWKKTXBGWHRJIBKEDBJWZABUXWHEHUXOXCU';
  const ct = CIPHERS.quagmire2.encrypt(pt, key);
  assertEq(ct, expectedCt, 'Quagmire II (ACA reference)');
  assertEq(CIPHERS.quagmire2.decrypt(ct, key), pt, 'Quagmire II decrypt round-trip');
}

// --- Quagmire III (ACA reference) ---
{
  const key = { keyword1: 'AUTOMOBILE', indicator: 'HIGHWAY' };
  const pt = 'THESAMEKEYEDALPHABETISUSEDFORPLAINANDCIPHERALPHABETS';
  const expectedCt = 'KRSLWMITJDVIABMRGQMTMLLIVIFUIXRHTNYONVRHHIIIRMCAOVEI';
  const ct = CIPHERS.quagmire3.encrypt(pt, key);
  assertEq(ct, expectedCt, 'Quagmire III (ACA reference)');
  assertEq(CIPHERS.quagmire3.decrypt(ct, key), pt, 'Quagmire III decrypt round-trip');
}

// --- Quagmire III: Kryptos K1 ---
{
  const key = { keyword1: 'KRYPTOS', indicator: 'PALIMPSEST' };
  const pt = 'BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION';
  const expectedCt = 'EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFD';
  const ct = CIPHERS.quagmire3.encrypt(pt, key);
  assertEq(ct, expectedCt, 'Quagmire III (Kryptos K1)');
}

// --- Quagmire III: Kryptos K2 (first stretch, to keep it short) ---
{
  const key = { keyword1: 'KRYPTOS', indicator: 'ABSCISSA' };
  const expectedCtPrefix = 'VFPJUDEEHZWETZYVGWHKKQETGFQJNCEGGWHKKDQMCPFQZDQMMIAGPFXHQRLGTIMVMZJANQLVKQEDAGDV';
  const fullPt = 'ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELDXTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATIONX';
  const pt = fullPt.slice(0, expectedCtPrefix.length);
  const ct = CIPHERS.quagmire3.encrypt(pt, key);
  assertEq(ct, expectedCtPrefix, 'Quagmire III (Kryptos K2 prefix)');
}

// --- Quagmire IV (ACA reference) ---
{
  const key = { keyword1: 'SENSORY', keyword2: 'PERCEPTION', indicator: 'EXTRA' };
  const pt = 'THISONEEMPLOYSTHREEKEYWORDS';
  const expectedCt = 'VBMRFCYISPMPBRRHEICXRREIGDX';
  const ct = CIPHERS.quagmire4.encrypt(pt, key);
  assertEq(ct, expectedCt, 'Quagmire IV (ACA reference)');
  assertEq(CIPHERS.quagmire4.decrypt(ct, key), pt, 'Quagmire IV decrypt round-trip');
}

// --- Running Key ACA (official ACA "Cryptogram" worked example) ---
{
  const key = { keyText: 'THISCIPHERCANBEUSEDW' };
  const pt = 'ITHANYOFTHEPERIODICS';
  const expectedCt = 'BAPSPGDMXYGPRSMIVMFO';
  const ct = CIPHERS.running_key_aca.encrypt(pt, key);
  assertEq(ct, expectedCt, 'Running Key ACA (official ACA reference example)');
  assertEq(CIPHERS.running_key_aca.decrypt(ct, key), pt, 'Running Key ACA decrypt round-trip');
}

// --- Running Key ACA randomKey: uses adjacent preceding text when given, falls back otherwise ---
{
  const withAdjacent = CIPHERS.running_key_aca.randomKey({ ptLength: 5, precedingText: 'XXXHELLO' });
  assertEq(withAdjacent.key.keyText, 'HELLO', 'Running Key ACA randomKey uses the last N chars of precedingText');

  const withShortAdjacent = CIPHERS.running_key_aca.randomKey({ ptLength: 10, precedingText: 'AB' });
  assertTrue(withShortAdjacent.key.keyText.length >= 10, 'Running Key ACA randomKey falls back to a full-length key when precedingText is too short');
}

// --- generator.js: precedingText returned by pickPlaintextSequence is exactly
// the (no-spaces) text immediately before the chosen plaintext in the same
// corpus source, i.e. a genuine continuation, not unrelated text. ---
{
  const G = global.CipherGenerator;
  let checked = 0;
  for (let i = 0; i < 30 && checked < 8; i++) {
    const seq = G.pickPlaintextSequence(60, 4000);
    if (!seq) continue;
    const src = (global.CIPHERGEN_CORPORA || []).find((c) => c.file === seq.corpusFile);
    const words = src.text.split(' ').filter(Boolean);
    const expected = words.slice(0, seq.startIndex).join('').slice(-60);
    checked++;
    assertEq(seq.precedingText, expected, 'precedingText is exactly the text immediately before the chosen plaintext in the same source');
  }
  assertTrue(checked > 0, 'precedingText coverage check ran at least once');
}

// --- generator.js: pickForCiphertextLength must never produce a ciphertext
// longer than the requested target length, for every registered cipher -
// including the ones that fractionate/expand (Homophonic, ADFGX, ADFGVX,
// x2), pad to a block size (Hill) or insert content-dependent fillers
// (Playfair), and add fixed overhead (Mirdek's 25-letter IV). Ciphers whose
// plaintext:ciphertext length relationship is an exact, content-independent
// ratio (the large majority - simple substitution, Vigenere-family,
// transposition-family, Bifid/Trifid, etc., plus Homophonic/ADFGX/ADFGVX's
// exact x2 and Mirdek's exact +25) must hit the target exactly whenever it's
// achievable at all (an odd target for a x2 cipher, or a target under
// Mirdek's 25-letter floor, can only be undershot, never hit exactly - the
// hard requirement is still that it's never exceeded). Playfair/Hill's
// padding depends on the actual letters chosen, so only "never exceeds, and
// isn't wildly short" is checked for those. ---
{
  const G = global.CipherGenerator;
  const CIPHERS_ALL = global.CipherLib.CIPHERS;
  const EXACT_RATIO2 = new Set(['homophonic_substitution', 'adfgx', 'adfgvx']);
  const VARIABLE_OVERHEAD = new Set(['playfair', 'hill']);
  const targets = [40, 61, 97]; // includes an odd target to stress ratio-2 ciphers' parity limit

  for (const id of Object.keys(CIPHERS_ALL)) {
    const def = CIPHERS_ALL[id];
    for (const target of targets) {
      if (id === 'mirdek' && target <= 25) continue; // below Mirdek's fixed IV floor - not achievable at all, correctly returns null
      const found = G.pickForCiphertextLength(def, id, target, 30);
      assertTrue(!!found, `${id}: pickForCiphertextLength(${target}) found a usable plaintext/key/ciphertext`);
      if (!found) continue;
      assertTrue(found.ciphertext.length <= target, `${id}: ciphertext length (${found.ciphertext.length}) must never exceed the target (${target})`);
      if (EXACT_RATIO2.has(id)) {
        const bestPossible = target % 2 === 0 ? target : target - 1;
        assertEq(found.ciphertext.length, bestPossible, `${id}: exact x2 ratio should hit ${bestPossible} for target ${target}`);
      } else if (id === 'mirdek') {
        assertEq(found.ciphertext.length, target, `${id}: exact +25 offset should hit the target exactly (${target})`);
      } else if (!VARIABLE_OVERHEAD.has(id)) {
        assertEq(found.ciphertext.length, target, `${id}: exact 1:1 ratio should hit the target exactly (${target})`);
      } else {
        assertTrue(found.ciphertext.length >= target - 5, `${id}: content-dependent padding should still land close to the target (${target}), got ${found.ciphertext.length}`);
      }
      // (Not re-checked here: decrypt(returned ciphertext) reproducing the
      // returned plaintext exactly - that's the existing generic round-trip
      // suite's job above, and on arbitrary corpus text several ciphers have
      // known, pre-existing lossy edge cases unrelated to length-targeting
      // - Playfair/ADFGX/Bifid merge J into I, Playfair inserts fillers for
      // double letters/odd length, and Hill's block padding survives into
      // decrypt's output - so it's not a valid universal invariant here.)
    }
  }
}

// --- generator.js: pickForCiphertextLength in length-*range* mode
// (`{min, max}` instead of a plain number) - a number and the degenerate
// range `{min: n, max: n}` must behave identically, and a real range must
// land the ciphertext length somewhere inside [min, max] for every
// registered cipher, including the ratio-2 (Homophonic/ADFGX/ADFGVX) and
// variable-overhead (Playfair/Hill) ciphers that can't hit an arbitrary
// exact length - the whole point of range mode. ---
{
  const G = global.CipherGenerator;
  const CIPHERS_ALL = global.CipherLib.CIPHERS;

  for (const id of Object.keys(CIPHERS_ALL)) {
    const def = CIPHERS_ALL[id];
    // A number and {min:60,max:60} must search identically.
    const asNumber = G.pickForCiphertextLength(def, id, 60, 30);
    const asDegenerateRange = G.pickForCiphertextLength(def, id, { min: 60, max: 60 }, 30);
    assertEq(!!asNumber, !!asDegenerateRange, `${id}: a number target and the equivalent degenerate {min,max} range must both succeed or both fail`);
    if (asNumber) assertEq(asNumber.ciphertext.length, asDegenerateRange.ciphertext.length, `${id}: a number target and the equivalent degenerate {min,max} range must find the same ciphertext length`);

    // A real range: every cipher (including ratio-2 and variable-overhead
    // ones) should be able to land somewhere in a reasonably wide window.
    if (id === 'mirdek') continue; // Mirdek's fixed +25 overhead means this specific window is unreachable; covered separately below.
    const found = G.pickForCiphertextLength(def, id, { min: 90, max: 100 }, 30);
    assertTrue(!!found, `${id}: pickForCiphertextLength({min:90,max:100}) found a usable plaintext/key/ciphertext`);
    if (!found) continue;
    assertTrue(found.ciphertext.length >= 90 && found.ciphertext.length <= 100, `${id}: ciphertext length (${found.ciphertext.length}) must fall within the requested range [90,100]`);
  }

  // Mirdek: a range comfortably clear of the 25-letter IV floor works normally.
  {
    const found = G.pickForCiphertextLength(CIPHERS_ALL.mirdek, 'mirdek', { min: 90, max: 100 }, 30);
    assertTrue(!!found, 'mirdek: pickForCiphertextLength({min:90,max:100}) found a usable plaintext/key/ciphertext');
    if (found) assertTrue(found.ciphertext.length >= 90 && found.ciphertext.length <= 100, `mirdek: ciphertext length (${found.ciphertext.length}) must fall within the requested range [90,100]`);
  }

  // A range entirely below Mirdek's 25-letter IV floor can never be hit -
  // correctly returns null rather than an out-of-range result.
  {
    const found = G.pickForCiphertextLength(CIPHERS_ALL.mirdek, 'mirdek', { min: 5, max: 10 }, 30);
    assertTrue(!found, 'mirdek: a range entirely below the 25-letter IV floor is correctly unreachable');
  }

  // Repeated calls in range mode must land on *varied* lengths spread
  // across the range - not the same one every time (e.g. always the
  // range's midpoint) - since each call seeds its search from a fresh
  // random point in the range. A wide-enough range and a decent sample
  // size make it astronomically unlikely every draw lands identically by
  // chance alone for an exact-ratio cipher like Vigenere.
  {
    const lengths = new Set();
    for (let i = 0; i < 20; i++) {
      const found = G.pickForCiphertextLength(CIPHERS_ALL.vigenere, 'vigenere', { min: 50, max: 150 }, 30);
      if (found) lengths.add(found.ciphertext.length);
    }
    assertTrue(lengths.size > 1, `pickForCiphertextLength(range) should land on varied lengths across repeated calls, not always the same one (got: ${[...lengths].join(',')})`);
  }
}

// --- generator.js: generateCiphersAsync accepts a lengthSpec range and
// keeps every produced ciphertext inside it; generateBulkAsync runs every
// requested cipher type in turn, calling onCipherDone once per type (with
// that type's own results) and onAllDone exactly once at the end with all
// of them combined. ---
{
  const G = global.CipherGenerator;

  // generateCiphersAsync, range mode, single cipher type.
  {
    let doneResults = null, doneSkipped = null;
    G.generateCiphersAsync({
      cipherId: 'vigenere',
      lengthSpec: { min: 30, max: 40 },
      quantity: 5,
      isCancelled: () => false,
      onProgress: () => {},
      onDone: (results, skipped) => { doneResults = results; doneSkipped = skipped; },
      onError: (e) => { throw e; },
    });
    assertEq(doneResults && doneResults.length, 5, 'generateCiphersAsync (range mode) produced the requested quantity');
    assertTrue(doneSkipped === 0, 'generateCiphersAsync (range mode) skipped none for an easy cipher/range');
    (doneResults || []).forEach((r) => {
      assertTrue(r.ciphertext.length >= 30 && r.ciphertext.length <= 40, `generateCiphersAsync (range mode): ciphertext length (${r.ciphertext.length}) must fall within [30,40]`);
    });
  }

  // generateBulkAsync across a handful of cipher types. This genuinely
  // spans multiple event-loop turns (it setTimeouts between cipher types),
  // so it's queued as an async test and drained near the bottom of this
  // file rather than asserted on immediately.
  asyncTest((done) => {
    const cipherIds = ['vigenere', 'beaufort', 'columnar_transposition'];
    const startedIds = [];
    const doneIds = [];
    G.generateBulkAsync({
      cipherIds,
      lengthSpec: 24,
      quantity: 3,
      isCancelled: () => false,
      onCipherStart: (cipherId) => startedIds.push(cipherId),
      onCipherDone: (cipherId, results, skipped) => {
        doneIds.push(cipherId);
        assertEq(results.length, 3, `generateBulkAsync: ${cipherId} produced the requested quantity`);
        results.forEach((r) => assertEq(r.ciphertext.length, 24, `generateBulkAsync: ${cipherId} ciphertext length must hit the exact target (24)`));
      },
      onAllDone: (allDoneByType, allDoneCancelled) => {
        assertEq(startedIds.join(','), cipherIds.join(','), 'generateBulkAsync: onCipherStart fires for every cipher type, in order');
        assertEq(doneIds.join(','), cipherIds.join(','), 'generateBulkAsync: onCipherDone fires for every cipher type, in order');
        assertTrue(!allDoneCancelled, 'generateBulkAsync: onAllDone reports not cancelled');
        assertEq(allDoneByType && allDoneByType.length, cipherIds.length, 'generateBulkAsync: onAllDone receives every cipher type\'s results');
        assertEq((allDoneByType || []).reduce((n, t) => n + t.results.length, 0), cipherIds.length * 3, 'generateBulkAsync: onAllDone\'s combined result count matches quantity * cipher types');
        done();
      },
      onError: (e) => { throw e; },
    });
  });

  // generateBulkAsync respects isCancelled between cipher types.
  asyncTest((done) => {
    const cipherIds = ['vigenere', 'beaufort', 'columnar_transposition', 'porta'];
    const cancelAfter = 2; // cancel once this many types have completed
    const doneIds = [];
    G.generateBulkAsync({
      cipherIds,
      lengthSpec: 24,
      quantity: 2,
      isCancelled: () => doneIds.length >= cancelAfter,
      onCipherDone: (cipherId) => doneIds.push(cipherId),
      onAllDone: (byType, wasCancelled) => {
        assertTrue(wasCancelled, 'generateBulkAsync: onAllDone reports cancelled when isCancelled becomes true mid-run');
        assertTrue(doneIds.length < cipherIds.length, 'generateBulkAsync: stops before every cipher type runs once cancelled');
        done();
      },
      onError: (e) => { throw e; },
    });
  });
}

// --- Running Key I-IV cross-checked against the already-verified Quagmire
// I-IV vectors above: for a plaintext no longer than the indicator word,
// `indicator[i % indicator.length] === indicator[i]` for every position, so
// Running Key I-IV (which use the running key text directly at position i,
// with no cycling) must reproduce an exact prefix of the matching Quagmire
// ciphertext when the running key text equals that indicator word. This
// isn't numerical luck - the two implementations execute the identical
// per-position formula on this input, differing only in how far K(i) can be
// read from. ---
{
  // Running Key I <-> Quagmire I (ACA reference), truncated to indicator length (6).
  let key = { keyword1: 'SPRINGFEVER', runningKey: { keyText: 'FLOWER' } };
  assertEq(CIPHERS.running_key1.encrypt('THEQUA', key), 'QPMGQR', 'Running Key I matches Quagmire I prefix');
  assertEq(CIPHERS.running_key1.decrypt('QPMGQR', key), 'THEQUA', 'Running Key I decrypt round-trip');

  // Running Key II <-> Quagmire II (ACA reference), truncated to indicator length (6).
  key = { keyword1: 'SPRINGFEVER', runningKey: { keyText: 'FLOWER' } };
  assertEq(CIPHERS.running_key2.encrypt('INTHEQ', key), 'JICICO', 'Running Key II matches Quagmire II prefix');
  assertEq(CIPHERS.running_key2.decrypt('JICICO', key), 'INTHEQ', 'Running Key II decrypt round-trip');

  // Running Key III <-> Quagmire III (ACA reference), truncated to indicator length (7).
  key = { keyword1: 'AUTOMOBILE', runningKey: { keyText: 'HIGHWAY' } };
  assertEq(CIPHERS.running_key3.encrypt('THESAME', key), 'KRSLWMI', 'Running Key III matches Quagmire III prefix (ACA)');
  assertEq(CIPHERS.running_key3.decrypt('KRSLWMI', key), 'THESAME', 'Running Key III decrypt round-trip');

  // Running Key III <-> Quagmire III via real Kryptos K1, truncated to indicator length (10).
  key = { keyword1: 'KRYPTOS', runningKey: { keyText: 'PALIMPSEST' } };
  assertEq(CIPHERS.running_key3.encrypt('BETWEENSUB', key), 'EMUFPHZLRF', 'Running Key III matches Quagmire III prefix (Kryptos K1)');

  // Running Key IV <-> Quagmire IV (ACA reference), truncated to indicator length (5).
  key = { keyword1: 'SENSORY', keyword2: 'PERCEPTION', runningKey: { keyText: 'EXTRA' } };
  assertEq(CIPHERS.running_key4.encrypt('THISO', key), 'VBMRF', 'Running Key IV matches Quagmire IV prefix');
  assertEq(CIPHERS.running_key4.decrypt('VBMRF', key), 'THISO', 'Running Key IV decrypt round-trip');
}

// --- Running Key + Transposition / Transposition + Running Key: hand-worked vectors ---
// pt="ATTACKATDAWN", running key text "QWERTYUIOPAS" (12 letters, matches pt length).
// Columnar transposition keyword "ZEBRA" -> column read order [4,2,1,3,0]
// (grid: col0=[0,5,10] col1=[1,6,11] col2=[2,7] col3=[3,8] col4=[4,9]).
{
  const pt = 'ATTACKATDAWN';
  const runningKey = { keyText: 'QWERTYUIOPAS' };
  const columnarTrans = { mode: 'columnar', keyword: 'ZEBRA' };
  const periodicTrans = { mode: 'periodic', period: 4, rank: [2, 0, 3, 1] }; // numeric key "3,1,4,2"

  // running key first (C0 = QPXRVIUBRPWF), then columnar-transpose C0.
  {
    const key = { runningKey, transposition: columnarTrans };
    const ct = CIPHERS.running_key_transposition.encrypt(pt, key);
    assertEq(ct, 'VPXBPUFRRQIW', 'Running Key + Transposition (columnar), hand-worked');
    assertEq(CIPHERS.running_key_transposition.decrypt(ct, key), pt, 'Running Key + Transposition (columnar) decrypt round-trip');
  }
  // running key first, then simple-periodic-transpose C0.
  {
    const key = { runningKey, transposition: periodicTrans };
    const ct = CIPHERS.running_key_transposition.encrypt(pt, key);
    assertEq(ct, 'PIPRBFQVRXUW', 'Running Key + Transposition (simple periodic), hand-worked');
    assertEq(CIPHERS.running_key_transposition.decrypt(ct, key), pt, 'Running Key + Transposition (simple periodic) decrypt round-trip');
  }
  // columnar-transpose pt first (CATTTANADAKW), then running-key-encrypt that.
  {
    const key = { transposition: columnarTrans, runningKey };
    const ct = CIPHERS.transposition_running_key.encrypt(pt, key);
    assertEq(ct, 'SWXKMYHIRPKO', 'Transposition + Running Key (columnar), hand-worked');
    assertEq(CIPHERS.transposition_running_key.decrypt(ct, key), pt, 'Transposition + Running Key (columnar) decrypt round-trip');
  }
}

// --- Transposition key auto-detection (keyFromValues) ---
{
  const periodic = CIPHERS.running_key_transposition.keyFromValues({ keyText: 'ABCDEFGHIJKL', transKey: '3, 1, 4, 2' });
  assertEq(periodic.transposition.mode, 'periodic', 'Numeric transposition key auto-detected as periodic');
  assertEq(periodic.transposition.rank.join(','), '2,0,3,1', 'Periodic transposition key parsed to correct 0-based rank');

  const columnar = CIPHERS.running_key_transposition.keyFromValues({ keyText: 'ABCDEFGHIJKL', transKey: 'ZEBRA' });
  assertEq(columnar.transposition.mode, 'columnar', 'Alphabetic transposition key auto-detected as columnar');

  let threw = false;
  try { CIPHERS.running_key_transposition.keyFromValues({ keyText: 'ABCDEFGHIJKL', transKey: '1,1,2' }); }
  catch (e) { threw = true; }
  assertTrue(threw, 'Non-permutation periodic transposition key is rejected');
}

// --- Solitaire (Pontifex), all three official worked examples from
// schneier.com/academic/solitaire, plus the "DONOTUSEPC" keystream-arithmetic
// example ---
{
  // Sample 1: unkeyed deck, plaintext "AAAAA AAAAA"
  const ct1 = CIPHERS.solitaire.encrypt('AAAAAAAAAA', { passphrase: '' });
  assertEq(ct1, 'EXKYIZSGEH', 'Solitaire Sample 1 (unkeyed deck)');
  assertEq(CIPHERS.solitaire.decrypt(ct1, { passphrase: '' }), 'AAAAAAAAAA', 'Solitaire Sample 1 decrypt round-trip');

  // Sample 2: passphrase "FOO", plaintext all As
  const ct2 = CIPHERS.solitaire.encrypt('AAAAAAAAAAAAAAA', { passphrase: 'FOO' });
  assertEq(ct2, 'ITHZUJIWGRFARMW', 'Solitaire Sample 2 (passphrase FOO)');

  // Sample 3: passphrase "CRYPTONOMICON", message "SOLITAIRE" (padded to 10 with X)
  const ct3 = CIPHERS.solitaire.encrypt('SOLITAIREX', { passphrase: 'CRYPTONOMICON' });
  assertEq(ct3, 'KIRAKSFJAN', 'Solitaire Sample 3 (passphrase CRYPTONOMICON)');
  assertEq(CIPHERS.solitaire.decrypt(ct3, { passphrase: 'CRYPTONOMICON' }), 'SOLITAIREX', 'Solitaire Sample 3 decrypt round-trip');
}

// --- Mirdek, the complete worked example from
// ciphergoth.org/crypto/mirdek/example.html (every intermediate pile state
// in that example was hand-verified against this implementation while
// building it) ---
{
  const key = { iv: 'IPDZOWKGSTVARMEQYBCFJNHUL', passphrase: 'KEYPHRASE' };
  const ct = CIPHERS.mirdek.encrypt('PLAINTEXTX', key);
  assertEq(ct, 'IPDZOWKGSTVARMEQYBCFJNHULOYNYGIMYOE', 'Mirdek (ciphergoth.org worked example)');
  assertEq(CIPHERS.mirdek.decrypt(ct, key), 'PLAINTEXTX', 'Mirdek decrypt round-trip');
}

// --- Chaocipher, cross-referenced against a vector generated by dcode.gr's
// Chaocipher tool (the K1 plaintext, encrypted with a specific pair of disk
// alphabets) ---
{
  const key = { leftAlphabet: 'XLEMFHIWOVNYRUDQCJPASGBTKZ', rightAlphabet: 'SGLBIZHJMFTRXAVKNQPDWYCUOE' };
  const pt = 'BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION';
  const expectedCt = 'MKOJGSYVCIXMDEIWFBRVDBYUVFLXRZUSGIHQEESLBMZJHKAIZHXPIYFVTCVBFME';
  const ct = CIPHERS.chaocipher.encrypt(pt, key);
  assertEq(ct, expectedCt, 'Chaocipher (dcode.gr reference vector)');
  assertEq(CIPHERS.chaocipher.decrypt(ct, key), pt, 'Chaocipher decrypt round-trip');
  assertEq(CIPHERS.chaocipher.decrypt(expectedCt, key), pt, 'Chaocipher decrypts the dcode.gr ciphertext directly');
}

// --- Chaocipher variants. There's no external reference for these (they're
// original variations, not historical ciphers), so correctness is
// established by deriving each one's expected behavior from the
// already-verified real Chaocipher above rather than an arbitrary locked-in
// vector: three of the four variants keep Chaocipher's exact lookup rule
// (find the letter, read the corresponding letter off the other disk) and
// only change how the disks get permuted *afterward* - so their very first
// output letter, computed before either disk has been touched, must equal
// real Chaocipher's first output letter on the same two starting disks
// (all cross-checked against the shared 'BETWEENSUBTLE...' plaintext and
// disks used in the reference vector above); only later letters can diverge
// once each variant's own permutation rule has taken effect. ---
{
  const LEFT = 'XLEMFHIWOVNYRUDQCJPASGBTKZ';
  const RIGHT = 'SGLBIZHJMFTRXAVKNQPDWYCUOE';
  const PT = 'BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION';
  const REAL_CT = 'MKOJGSYVCIXMDEIWFBRVDBYUVFLXRZUSGIHQEESLBMZJHKAIZHXPIYFVTCVBFME';
  const key = { leftAlphabet: LEFT, rightAlphabet: RIGHT };

  // Chaocipher: Symmetric Wheels - same first letter as real Chaocipher
  // (neither disk has been permuted yet), diverging from letter 2 onward
  // since the two disks are now permuted identically instead of Byrne's
  // asymmetric rule. Vector locked in from this implementation.
  {
    const ct = CIPHERS.chaocipher_symmetric.encrypt(PT, key);
    assertEq(ct[0], REAL_CT[0], 'Chaocipher: Symmetric Wheels matches real Chaocipher on the (pre-permutation) first letter');
    assertTrue(ct !== REAL_CT, 'Chaocipher: Symmetric Wheels diverges from real Chaocipher once permutation starts');
    assertEq(ct, 'MZNSZZCXTMNEZXIUAFCLUCANIZUMXZCBZKVEFLINEFZXNIZCTUCBZKVFJETXFKC', 'Chaocipher: Symmetric Wheels vector');
    assertEq(CIPHERS.chaocipher_symmetric.decrypt(ct, key), PT, 'Chaocipher: Symmetric Wheels decrypt round-trip');
  }

  // Chaocipher: Adjustable Cut Point - cutPosition 13 (the nadir) is
  // mathematically identical to real Chaocipher's own fixed splice point,
  // so it must reproduce the *entire* reference ciphertext exactly, not
  // just the first letter. A different cut position still matches on the
  // untouched first letter, then diverges.
  {
    const key13 = CIPHERS.chaocipher_adjustable_cut.keyFromValues({ leftAlphabet: LEFT, rightAlphabet: RIGHT, cutPosition: '13' });
    const ct13 = CIPHERS.chaocipher_adjustable_cut.encrypt(PT, key13);
    assertEq(ct13, REAL_CT, 'Chaocipher: Adjustable Cut Point with cutPosition=13 is mathematically identical to real Chaocipher');
    assertEq(CIPHERS.chaocipher_adjustable_cut.decrypt(ct13, key13), PT, 'Chaocipher: Adjustable Cut Point (cut=13) decrypt round-trip');

    const key7 = CIPHERS.chaocipher_adjustable_cut.keyFromValues({ leftAlphabet: LEFT, rightAlphabet: RIGHT, cutPosition: '7' });
    const ct7 = CIPHERS.chaocipher_adjustable_cut.encrypt(PT, key7);
    assertEq(ct7[0], REAL_CT[0], 'Chaocipher: Adjustable Cut Point (cut=7) matches real Chaocipher on the first letter');
    assertTrue(ct7 !== REAL_CT, 'Chaocipher: Adjustable Cut Point (cut=7) diverges from real Chaocipher once permutation starts');
    assertEq(ct7, 'MKOJGSFALPSPDDXXEYPNEVPFTOKSBEZTVVEQEGZLUTTSHVYUQMCAZXCSKDMQBFX', 'Chaocipher: Adjustable Cut Point (cut=7) vector');
    assertEq(CIPHERS.chaocipher_adjustable_cut.decrypt(ct7, key7), PT, 'Chaocipher: Adjustable Cut Point (cut=7) decrypt round-trip');

    let threw = false;
    try { CIPHERS.chaocipher_adjustable_cut.keyFromValues({ leftAlphabet: LEFT, rightAlphabet: RIGHT, cutPosition: '25' }); }
    catch (e) { threw = true; }
    assertTrue(threw, 'Chaocipher: Adjustable Cut Point rejects an out-of-range cut position (25)');
  }

  // Chaocipher: Double Splice - independently re-derived (not just calling
  // its own encrypt() twice) by driving the already-verified chaoStep
  // primitive by hand, twice per letter.
  {
    const CL = global.CipherLib;
    let left = LEFT.split(''), right = RIGHT.split('');
    let manualCt = '';
    for (const ch of PT.slice(0, 6)) {
      const i = right.indexOf(ch);
      manualCt += left[i];
      [left, right] = CL.chaoStep(left, right, i);
      [left, right] = CL.chaoStep(left, right, i);
    }
    const ct = CIPHERS.chaocipher_double_splice.encrypt(PT.slice(0, 6), key);
    assertEq(ct, manualCt, 'Chaocipher: Double Splice matches independently hand-driven double chaoStep application');
    assertEq(ct[0], REAL_CT[0], 'Chaocipher: Double Splice matches real Chaocipher on the (pre-permutation) first letter');

    const fullCt = CIPHERS.chaocipher_double_splice.encrypt(PT, key);
    assertEq(fullCt, 'MTIQAJPDOZPPIREHQRJHAEGYZWBVULGKPVAINQUWQPVQBNSBTQMZKLKICTXAHIQ', 'Chaocipher: Double Splice vector (full plaintext)');
    assertEq(CIPHERS.chaocipher_double_splice.decrypt(fullCt, key), PT, 'Chaocipher: Double Splice decrypt round-trip');
  }

  // Chaocipher: Single Wheel - structurally different (one shared alphabet,
  // offset-13 lookup instead of two independent disks), so it can't be
  // cross-checked against real Chaocipher's first letter the way the other
  // three can. Instead, hand-verify the very first letter directly from the
  // unpermuted starting wheel: 'A' sits at index 19 in LEFT (used here as
  // the wheel), so its ciphertext partner is the letter 13 positions (half
  // the 26-letter wheel) away, at index (19+13) mod 26 = 6, which is 'I'.
  {
    const singleKey = { wheelAlphabet: LEFT };
    assertEq(LEFT.indexOf('A'), 19, 'Chaocipher: Single Wheel - sanity-check letter A\'s starting index in the wheel used below');
    assertEq(LEFT[6], 'I', 'Chaocipher: Single Wheel - sanity-check the letter opposite A (index 19+13 mod 26 = 6)');
    assertEq(CIPHERS.chaocipher_single_wheel.encrypt('A', singleKey), 'I', 'Chaocipher: Single Wheel hand-verified first letter (A -> I, opposite side of the wheel)');
    assertEq(CIPHERS.chaocipher_single_wheel.decrypt('I', singleKey), 'A', 'Chaocipher: Single Wheel decrypts a single letter back (opposite is its own inverse: 13+13=26)');

    const ct = CIPHERS.chaocipher_single_wheel.encrypt(PT, singleKey);
    assertEq(ct, 'VCVNQDIJXIIKPQBPAOOIDTANMLDGPRQNVFHUKOOHAKXAITXYZPJUXKQVYWDRLBG', 'Chaocipher: Single Wheel vector (full plaintext)');
    assertEq(CIPHERS.chaocipher_single_wheel.decrypt(ct, singleKey), PT, 'Chaocipher: Single Wheel decrypt round-trip');
  }
}

// --- Move-to-Front / Move-to-Back, hand-worked vectors (keyword "ABC" ->
// starting alphabet is just straight A-Z, so the arithmetic is easy to
// check by hand: plaintext "BANANA" repeatedly re-uses B/A/N, so each
// cipher's characteristic drift is visible within a few letters) ---
{
  const key = { keyword: 'ABC' };
  const ctF = CIPHERS.move_to_front.encrypt('BANANA', key);
  assertEq(ctF, 'BBNBBB', 'Move-to-Front hand-worked vector (BANANA)');
  assertEq(CIPHERS.move_to_front.decrypt(ctF, key), 'BANANA', 'Move-to-Front decrypt round-trip');

  const ctB = CIPHERS.move_to_back.encrypt('BANANA', key);
  assertEq(ctB, 'BALYYY', 'Move-to-Back hand-worked vector (BANANA)');
  assertEq(CIPHERS.move_to_back.decrypt(ctB, key), 'BANANA', 'Move-to-Back decrypt round-trip');
}

// --- Dynamic Substitution (Ritter), hand-worked vector. Keywords "ABC" for
// both the alphabet and confusion streams collapse the starting table to
// straight A-Z and the "random" exchange index to a simple 0,1,2-repeating
// cycle, so the swap-by-swap arithmetic can be checked by hand: plaintext
// "BANANA" -> ciphertext "BBNACA" (worked by hand and cross-checked with an
// independent script before being locked in here; see the chat transcript /
// project notes for the full derivation). ---
{
  const key = { alphabetKeyword: 'ABC', confusionKeyword: 'ABC' };
  const ct = CIPHERS.dynamic_substitution.encrypt('BANANA', key);
  assertEq(ct, 'BBNACA', 'Dynamic Substitution hand-worked vector (BANANA)');
  assertEq(CIPHERS.dynamic_substitution.decrypt(ct, key), 'BANANA', 'Dynamic Substitution decrypt round-trip');

  // A second, longer round-trip with independent alphabet/confusion keywords
  // (and confusion shorter than the plaintext, so it wraps/cycles) guards
  // against the swap accidentally being symmetric only for short/matched keys.
  const key2 = { alphabetKeyword: 'PALIMPSEST', confusionKeyword: 'FEZ' };
  const pt2 = 'BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION';
  const ct2 = CIPHERS.dynamic_substitution.encrypt(pt2, key2);
  assertEq(CIPHERS.dynamic_substitution.decrypt(ct2, key2), pt2, 'Dynamic Substitution decrypt round-trip (longer text, cycling confusion key)');
}

// --- Vigenere textbook vector ---
{
  const key = { keyword: 'LEMON' };
  const ct = CIPHERS.vigenere.encrypt('ATTACKATDAWN', key);
  assertEq(ct, 'LXFOPVEFRNHR', 'Vigenere textbook vector');
}

// --- Beaufort self-reciprocal sanity ---
{
  const key = { keyword: 'FORTIFICATION' };
  const pt = 'DEFENDTHEEASTWALLOFTHECASTLE';
  const ct = CIPHERS.beaufort.encrypt(pt, key);
  assertEq(CIPHERS.beaufort.decrypt(ct, key), pt, 'Beaufort round-trip');
}

// --- Playfair textbook vector (Wikipedia "Playfair cipher" example) ---
{
  const key = { keyword: 'MONARCHY' };
  const ct = CIPHERS.playfair.encrypt('INSTRUMENTS', key);
  // "INSTRUMENTS" -> IN ST RU ME NT SX, hand-verified digraph by digraph
  // against the MONARCHY key square (IN->GA, ST->TL, RU->MZ, ME->CL, NT->RQ,
  // SX->XA via the same-column "shift down" rule).
  assertEq(ct, 'GATLMZCLRQXA', 'Playfair hand-verified vector (INSTRUMENTS)');
}

// --- Rail fence textbook vector ---
{
  const key = { rails: 3 };
  const ct = CIPHERS.rail_fence.encrypt('WEAREDISCOVEREDFLEEATONCE', key);
  assertEq(ct, 'WECRLTEERDSOEEFEAOCAIVDEN', 'Rail fence textbook vector (3 rails)');
  assertEq(CIPHERS.rail_fence.decrypt(ct, key), 'WEAREDISCOVEREDFLEEATONCE', 'Rail fence decrypt round-trip');
}

// --- Columnar transposition sanity (manual hand check) ---
{
  const key = { keyword: 'ZEBRA' };
  const pt = 'WEAREDISCOVEREDFLEEATONCE';
  const ct = CIPHERS.columnar_transposition.encrypt(pt, key);
  assertEq(CIPHERS.columnar_transposition.decrypt(ct, key), pt, 'Columnar transposition round-trip');
}

// --- Periodic transposition, hand-worked vectors (pt="ATTACKATDAWN", 12
// letters). interval=5 is coprime with 12, so it's a single 12-letter
// cycle (0,5,10,3,8,1,6,11,4,9,2,7 - worked by hand and cross-checked with
// an independent script); interval=4 shares a factor with 12 (gcd=4), so
// it's four separate 3-letter cycles (0,4,8 / 1,5,9 / 2,6,10 / 3,7,11)
// concatenated in the order they're started, exercising the
// multi-cycle/restart path. ---
{
  const pt = 'ATTACKATDAWN';
  const ct5 = CIPHERS.periodic_transposition.encrypt(pt, { interval: 5 });
  assertEq(ct5, 'AKWADTANCATT', 'Periodic transposition hand-worked vector (interval=5, single cycle)');
  assertEq(CIPHERS.periodic_transposition.decrypt(ct5, { interval: 5 }), pt, 'Periodic transposition decrypt round-trip (interval=5)');

  const ct4 = CIPHERS.periodic_transposition.encrypt(pt, { interval: 4 });
  assertEq(ct4, 'ACDTKATAWATN', 'Periodic transposition hand-worked vector (interval=4, gcd(4,12)=4, four 3-letter cycles)');
  assertEq(CIPHERS.periodic_transposition.decrypt(ct4, { interval: 4 }), pt, 'Periodic transposition decrypt round-trip (interval=4)');
}

// --- Inscription+Rotation transposition: Kryptos K3's actual, exact
// mechanism (write the plaintext into a 42x8 grid, rotate 90 clockwise
// (-> 8x42), inscribe the result into a 14x24 grid, rotate 90 clockwise
// again (-> 24x14)), checked against the real K3 plaintext and ciphertext
// (336 letters; K3's trailing "?" is dropped since these ciphers only
// carry A-Z). This exact grid-dimensions-and-rotations combination was
// found by brute-force search over fill/read order, rotation direction,
// and grid dimensions until the output matched the real K3 ciphertext -
// see the chat transcript / project notes for the full derivation.
//
// A separate, equally exhaustive search (every interval 1..335 combined
// with every starting offset 0..335, in both the "restart at next
// unvisited position" and the equivalent "counting-out"/Josephus
// formulations) found *no* parameterization of the Periodic transposition
// above that reproduces this same ciphertext letter-for-letter - so while
// "count off every 192nd letter" is a widely-repeated description of how
// to solve K3, it is a folk description of this double grid-rotation
// procedure (336 = 42x8 = 14x24, and 4x48 = 192 connects to the grid
// dimensions), not an independently exact algorithm in its own right. ---
{
  const K3_CT = 'ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIACHTNREYULDSLLSLLNOHSNOSMRWXMNETPRNGATIHNRARPESLNNELEBLPIIACAEWMTWNDITEENRAHCTENEUDRETNHAEOETFOLSEDTIWENHAEIOYTEYQHEENCTAYCREIFTBRSPAMHNEWENATAMATEGYEERLBTEEFOASFIOTUETUAEOTOARMAEERTNRTIBSEDDNIAAHTTMSTEWPIEROAGRIEWFEBAECTDDHILCEIHSITEGOEAOSDDRYDLORITRKLMLEHAGTDHARDPNEOHMGFMFEUHEECDMRIPFEIMEHNLSSTTRTVDOHW';
  const K3_PT = 'SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISTHATENCUMBEREDTHELOWERPARTOFTHEDOORWAYWASREMOVEDWITHTREMBLINGHANDSIMADEATINYBREACNINTHEUPPERLEFTHANDCORNERANDTHENWIDENINGTHEHOLEALITTLEIINSERTEDTHECANDLEANDPEEREDINTHEHOTAIRESCAPINGFROMTHECHAMBERCAUSEDTHEFLAMETOFLICKERBUTPRESENTLYDETAILSOFTHEROOMWITHINEMERGEDFROMTHEMISTXCANYOUSEEANYTHINGQ';
  assertEq(K3_CT.length, 336, 'K3 ciphertext reference vector is 336 letters');
  assertEq(K3_PT.length, 336, 'K3 plaintext reference vector is 336 letters');

  const values = { rows1: '42', cols1: '8', rotation1: 'CW90', rows2: '14', cols2: '24', rotation2: 'CW90' };
  const key = CIPHERS.inscription_rotation_transposition.keyFromValues(values);
  const ct = CIPHERS.inscription_rotation_transposition.encrypt(K3_PT, key);
  assertEq(ct, K3_CT, 'Inscription+Rotation (42x8 CW90, 14x24 CW90) reproduces the real Kryptos K3 ciphertext exactly');
  const pt = CIPHERS.inscription_rotation_transposition.decrypt(K3_CT, key);
  assertEq(pt, K3_PT, 'Inscription+Rotation decrypts the real Kryptos K3 ciphertext back to the real plaintext exactly');

  // keyFromValues round-trip (manual-mode path) reproduces the same key.
  const key2 = CIPHERS.inscription_rotation_transposition.keyFromValues(values);
  assertEq(CIPHERS.inscription_rotation_transposition.encrypt(K3_PT, key2), K3_CT, 'Inscription+Rotation keyFromValues reproduces the working K3 key');
}

// --- Inscription+Rotation: rejects mismatched grid/text sizes and
// mismatched grid products, and round-trips arbitrary rotation combos. ---
{
  let threw = false;
  try {
    CIPHERS.inscription_rotation_transposition.keyFromValues({ rows1: '3', cols1: '4', rotation1: 'CW90', rows2: '5', cols2: '2', rotation2: 'CW90' });
  } catch (e) { threw = true; }
  assertTrue(threw, 'Inscription+Rotation rejects grids whose products (letter counts) differ');

  threw = false;
  try {
    const key = CIPHERS.inscription_rotation_transposition.keyFromValues({ rows1: '3', cols1: '4', rotation1: 'CW90', rows2: '4', cols2: '3', rotation2: 'CCW90' });
    CIPHERS.inscription_rotation_transposition.encrypt('SHORT', key); // 5 letters != 12
  } catch (e) { threw = true; }
  assertTrue(threw, 'Inscription+Rotation rejects plaintext whose length does not match the first grid');

  // Every CW/CCW x 90/180/270 combination round-trips on a 3x4=12 grid.
  const pt = 'ABCDEFGHIJKL';
  for (const rotation1 of ['CW90', 'CW180', 'CW270', 'CCW90', 'CCW180', 'CCW270']) {
    for (const rotation2 of ['CW90', 'CW180', 'CW270', 'CCW90', 'CCW180', 'CCW270']) {
      const key = CIPHERS.inscription_rotation_transposition.keyFromValues({ rows1: '3', cols1: '4', rotation1, rows2: '4', cols2: '3', rotation2 });
      const ct = CIPHERS.inscription_rotation_transposition.encrypt(pt, key);
      assertEq(CIPHERS.inscription_rotation_transposition.decrypt(ct, key), pt, `Inscription+Rotation round-trip (${rotation1}, ${rotation2})`);
    }
  }
}

// --- Hill cipher textbook vector (2x2, "HELP" with key [[3,3],[2,5]]) ---
{
  const key = { size: 2, matrix: [[3, 3], [2, 5]] };
  const ct = CIPHERS.hill.encrypt('HELP', key);
  assertEq(ct, 'HIAT', 'Hill cipher textbook vector (HELP)');
  assertEq(CIPHERS.hill.decrypt(ct, key), 'HELP', 'Hill cipher decrypt round-trip');
}

// --- Enigma known-answer test (rotors I II III, ring AAA, pos AAA, reflector B, no plugboard) ---
{
  const key = { rotors: ['I', 'II', 'III'], ringSettings: [1, 1, 1], initialPositions: ['A', 'A', 'A'], reflector: 'B', plugboard: [] };
  const ct = CIPHERS.enigma.encrypt('AAAAA', key);
  console.log(`Enigma I-II-III AAA/AAA/B no plugboard, input AAAAA -> ${ct}`);
  assertTrue(ct.length === 5 && /^[A-Z]+$/.test(ct), 'Enigma produces 5 letters');
  assertEq(CIPHERS.enigma.decrypt(ct, key), 'AAAAA', 'Enigma self-reciprocal round-trip');
}

// --- Enigma: the "Gillogly" M3 test cipher (a well-known Enigma-cracking test
// vector - German naval-style message, plaintext ends "...der Fuehrer ist
// tot. Der Kampf geht weiter. Doenitz."), cross-checked against a real
// external Enigma solver (the "colossus" project's enigma_solver.c), whose
// reported settings for this exact ciphertext were:
//   M3 | reflector B | rotors II I III | rings AWD | pos BGI |
//   plugs BL EZ IU JO MV PX RW
// colossus's rotor[0] is documented as the LEFTMOST wheel and ring/pos are
// 0-based-as-letters (A=0), matching this tool's "left to right" fields
// exactly except ring settings, which this tool takes as 1-26 (so letter+1).
// This is a genuine external validation - not just internal round-tripping -
// and is what caught a real bug: buildEnigmaMachine() used to treat index 0
// as the *rightmost* rotor while its field label claimed "left to right".
{
  const ct = fs.readFileSync(path.join(__dirname, 'fixtures', 'enigma_gillogly.txt'), 'utf8').trim();
  const expectedPt = fs.readFileSync(path.join(__dirname, 'fixtures', 'enigma_gillogly.solution'), 'utf8').trim();
  const values = {
    rotors: 'II-I-III',
    ringSettings: '1-23-4', // letters A,W,D (0-based) -> 1-based 1,23,4
    initialPositions: 'BGI',
    reflector: 'B',
    plugboard: 'BL EZ IU JO MV PX RW',
  };
  const key = CIPHERS.enigma.keyFromValues(values);
  const pt = CIPHERS.enigma.decrypt(ct, key);
  assertEq(pt, expectedPt, 'Enigma decrypts the Gillogly M3 test cipher to the real German plaintext');
}

// --- ADFGX / ADFGVX / Bifid / Trifid / Myszkowski / Porta / Autokey / Running key / Scytale / Double columnar / Homophonic / Simple substitution round-trip already covered above generically ---

runAsyncTests(asyncTests, () => {
  console.log(`\n=== TOTAL: ${checks} checks, ${failures} failures ===`);
  process.exit(failures ? 1 : 0);
});

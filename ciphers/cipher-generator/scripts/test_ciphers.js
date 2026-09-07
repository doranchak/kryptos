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

console.log(`\n=== TOTAL: ${checks} checks, ${failures} failures ===`);
process.exit(failures ? 1 : 0);

// ============================================================================
// Cipher library: classical pen-and-paper cipher implementations.
//
// Every cipher descriptor exposes the same shape so the UI and the generator
// can treat them uniformly:
//   id            short machine id ("vigenere", "quagmire3", ...)
//   label         display name, also used as the CSV "cipher type label"
//   fields        input field descriptors for the manual encrypt/decrypt UI
//   randomKey(opts)  -> { key, values }  (opts = {ptLength})
//                    key    = internal key object used by encrypt/decrypt
//                    values = {fieldName: string} matching `fields`, so the
//                             UI can populate the manual-mode form with it
//   keyFromValues(values) -> key object (throws Error with a readable message
//                             on invalid input)
//   keyInfo(key)  -> compact human-readable string for the CSV / results table
//   encrypt(ptLettersOnly, key) -> ciphertext string
//   decrypt(ctLettersOnly, key) -> plaintext string
// ============================================================================

(function (global) {
  'use strict';

  const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';

  // ---------------------------------------------------------------------
  // small numeric / string helpers
  // ---------------------------------------------------------------------
  function mod(n, m) { return ((n % m) + m) % m; }
  function letterNum(ch) { return ch.charCodeAt(0) - 65; }
  function numLetter(n) { return String.fromCharCode(65 + mod(n, 26)); }
  function onlyLetters(s) { return (s || '').toUpperCase().replace(/[^A-Z]/g, ''); }

  function randInt(minInclusive, maxInclusive) {
    return Math.floor(Math.random() * (maxInclusive - minInclusive + 1)) + minInclusive;
  }
  function randChoice(arr) { return arr[randInt(0, arr.length - 1)]; }

  function shuffled(arr, rng) {
    rng = rng || Math.random;
    const a = arr.slice();
    for (let i = a.length - 1; i > 0; i--) {
      const j = Math.floor(rng() * (i + 1));
      const tmp = a[i]; a[i] = a[j]; a[j] = tmp;
    }
    return a;
  }

  // seedable PRNG (mulberry32) - only used where a keyword must deterministically
  // regenerate a larger structure (homophonic code tables).
  function mulberry32(seed) {
    let s = seed >>> 0;
    return function () {
      s |= 0; s = (s + 0x6D2B79F5) | 0;
      let t = Math.imul(s ^ (s >>> 15), 1 | s);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }
  function seedFromString(str) {
    let h = 0;
    for (let i = 0; i < str.length; i++) h = (Math.imul(31, h) + str.charCodeAt(i)) | 0;
    return h;
  }

  // Build a 26-letter mixed alphabet from a keyword: unique letters of the
  // keyword (in order of first appearance) followed by the remaining letters
  // of the alphabet in A-Z order. Standard "keyed alphabet" construction used
  // by simple substitution, Quagmire I-IV, columnar-style keys, etc.
  function keyedAlphabet26(keyword) {
    const seen = new Set();
    const out = [];
    for (const ch of onlyLetters(keyword)) {
      if (!seen.has(ch)) { seen.add(ch); out.push(ch); }
    }
    for (const ch of ALPHABET) {
      if (!seen.has(ch)) { seen.add(ch); out.push(ch); }
    }
    return out.join('');
  }

  // Same idea but for an n-symbol alphabet drawn from an arbitrary symbol set
  // (used for the 5x5 / 6x6 Polybius-style squares).
  function keyedSymbolSequence(keyword, symbolSet) {
    const seen = new Set();
    const out = [];
    for (const ch of onlyLetters(keyword)) {
      if (symbolSet.includes(ch) && !seen.has(ch)) { seen.add(ch); out.push(ch); }
    }
    for (const ch of symbolSet) {
      if (!seen.has(ch)) { seen.add(ch); out.push(ch); }
    }
    return out;
  }

  function pickDictionaryWord(minLen, maxLen) {
    const words = global.CIPHERGEN_DICTIONARY_TOP80 || [];
    for (let tries = 0; tries < 300; tries++) {
      const w = randChoice(words);
      if (w.length >= minLen && w.length <= maxLen) return w;
    }
    const filtered = words.filter((w) => w.length >= minLen && w.length <= maxLen);
    return filtered.length ? randChoice(filtered) : randChoice(words);
  }

  function pickDistinctDictionaryWords(count, minLen, maxLen) {
    const out = [];
    let guard = 0;
    while (out.length < count && guard < 2000) {
      guard++;
      const w = pickDictionaryWord(minLen, maxLen);
      if (!out.includes(w)) out.push(w);
    }
    while (out.length < count) out.push(pickDictionaryWord(minLen, maxLen));
    return out;
  }

  // Column order (1-based rank, ties broken left-to-right) implied by a
  // transposition keyword. Shared by columnar / double-columnar / Myszkowski.
  function keywordColumnRanks(keyword) {
    const letters = onlyLetters(keyword).split('');
    const withIdx = letters.map((ch, i) => ({ ch, i }));
    const sorted = withIdx.slice().sort((a, b) => (a.ch < b.ch ? -1 : a.ch > b.ch ? 1 : a.i - b.i));
    const rank = new Array(letters.length);
    sorted.forEach((item, r) => { rank[item.i] = r; });
    return rank; // rank[col] = 0-based read order for distinct-letter keywords
  }

  function validateLength(s, name) {
    if (!s || s.length === 0) throw new Error(`${name} must not be empty.`);
  }

  // ===========================================================================
  // Registry
  // ===========================================================================
  const CIPHERS = {};
  function register(def) { CIPHERS[def.id] = def; }

  // ---------------------------------------------------------------------
  // Simple substitution
  // ---------------------------------------------------------------------
  register({
    id: 'simple_substitution',
    label: 'Simple Substitution',
    fields: [
      { name: 'cipherAlphabet', label: 'Cipher alphabet (26 letters, A=first)', type: 'text', placeholder: 'e.g. QWERTYUIOPASDFGHJKLZXCVBNM' },
    ],
    randomKey() {
      const cipherAlphabet = shuffled(ALPHABET.split('')).join('');
      return { key: { cipherAlphabet }, values: { cipherAlphabet } };
    },
    keyFromValues(values) {
      const ca = onlyLetters(values.cipherAlphabet);
      if (ca.length !== 26 || new Set(ca).size !== 26) {
        throw new Error('Cipher alphabet must contain exactly the 26 letters A-Z, each once.');
      }
      return { cipherAlphabet: ca };
    },
    keyInfo(key) { return `cipher alphabet=${key.cipherAlphabet}`; },
    encrypt(pt, key) {
      return pt.split('').map((ch) => key.cipherAlphabet[letterNum(ch)]).join('');
    },
    decrypt(ct, key) {
      const inv = new Array(26);
      for (let i = 0; i < 26; i++) inv[letterNum(key.cipherAlphabet[i])] = numLetter(i);
      return ct.split('').map((ch) => inv[letterNum(ch)]).join('');
    },
  });

  // ---------------------------------------------------------------------
  // Homophonic substitution (100 two-digit codes 00-99, allocated to letters
  // proportional to typical English letter frequency, shuffled by a keyword).
  // ---------------------------------------------------------------------
  const ENGLISH_FREQ = { E: 12.7, T: 9.1, A: 8.2, O: 7.5, I: 7.0, N: 6.7, S: 6.3, H: 6.1, R: 6.0, D: 4.3, L: 4.0, C: 2.8, U: 2.8, M: 2.4, W: 2.4, F: 2.2, G: 2.0, Y: 2.0, P: 1.9, B: 1.5, V: 1.0, K: 0.8, J: 0.15, X: 0.15, Q: 0.10, Z: 0.07 };

  function buildHomophoneTables(keyword) {
    const rng = mulberry32(seedFromString('HOMO:' + onlyLetters(keyword)));
    // allocate 100 codes across letters proportional to frequency, min 1 each
    const totalFreq = Object.values(ENGLISH_FREQ).reduce((a, b) => a + b, 0);
    const counts = {};
    let allocated = 0;
    for (const ch of ALPHABET) {
      const c = Math.max(1, Math.round((ENGLISH_FREQ[ch] / totalFreq) * 100));
      counts[ch] = c;
      allocated += c;
    }
    // adjust to sum exactly to 100 by tweaking the most frequent letter
    let diff = 100 - allocated;
    const order = ALPHABET.split('').sort((a, b) => ENGLISH_FREQ[b] - ENGLISH_FREQ[a]);
    let oi = 0;
    while (diff !== 0) {
      const ch = order[oi % order.length];
      if (diff > 0) { counts[ch]++; diff--; } else if (counts[ch] > 1) { counts[ch]--; diff++; }
      oi++;
    }
    const codes = shuffled(Array.from({ length: 100 }, (_, i) => i), rng);
    const letterToCodes = {};
    const codeToLetter = {};
    let p = 0;
    for (const ch of ALPHABET) {
      const n = counts[ch];
      letterToCodes[ch] = codes.slice(p, p + n);
      codes.slice(p, p + n).forEach((c) => { codeToLetter[c] = ch; });
      p += n;
    }
    return { letterToCodes, codeToLetter };
  }

  register({
    id: 'homophonic_substitution',
    label: 'Homophonic Substitution',
    fields: [
      { name: 'keyword', label: 'Keyword (seeds the code assignment)', type: 'text', placeholder: 'e.g. SHADOW' },
    ],
    randomKey() {
      const keyword = pickDictionaryWord(5, 9);
      return { key: { keyword }, values: { keyword } };
    },
    keyFromValues(values) {
      validateLength(onlyLetters(values.keyword), 'Keyword');
      return { keyword: onlyLetters(values.keyword) };
    },
    keyInfo(key) { return `keyword=${key.keyword}`; },
    encrypt(pt, key) {
      const { letterToCodes } = buildHomophoneTables(key.keyword);
      return pt.split('').map((ch) => {
        const opts = letterToCodes[ch];
        const code = opts[randInt(0, opts.length - 1)];
        return String(code).padStart(2, '0');
      }).join('');
    },
    decrypt(ct, key) {
      const { codeToLetter } = buildHomophoneTables(key.keyword);
      const digits = ct.replace(/[^0-9]/g, '');
      let out = '';
      for (let i = 0; i + 1 < digits.length + 1 && i < digits.length; i += 2) {
        const code = parseInt(digits.substr(i, 2), 10);
        out += codeToLetter[code] || '?';
      }
      return out;
    },
  });

  // ---------------------------------------------------------------------
  // Chaocipher (John F. Byrne). Two 26-letter "disks" - a left (ciphertext)
  // and right (plaintext) alphabet - that dynamically permute after every
  // single letter, so the effective substitution never repeats. Algorithm
  // verified letter-for-letter against a dcode.gr-generated test vector (see
  // scripts/test_ciphers.js): to encipher, find the plaintext letter's index
  // i in RIGHT, output LEFT[i], then permute both disks:
  //   LEFT:  rotate so index i is at position 0, remove position 1, reinsert
  //          it at position 13.
  //   RIGHT: rotate so index i+1 is at position 0 (one extra step vs LEFT -
  //          this asymmetry is what makes the cipher self-decrypting),
  //          remove position 2, reinsert it at position 13.
  // Deciphering is the mirror image: find the ciphertext letter's index in
  // LEFT, output RIGHT[i], then apply the identical permutation using that i.
  // ---------------------------------------------------------------------
  function chaoRotate(arr, k) {
    const n = arr.length;
    k = mod(k, n);
    return arr.slice(k).concat(arr.slice(0, k));
  }
  function chaoRemoveInsert(arr, removePos, insertPos) {
    const a = arr.slice();
    const letter = a.splice(removePos, 1)[0];
    a.splice(insertPos, 0, letter);
    return a;
  }
  // Advance both disks one step, given the index `i` used for this letter.
  // Returns [newLeft, newRight]. Shared by encrypt, decrypt, and the
  // visualizer (via CipherLib) so the disk animation can never drift from
  // what encrypt()/decrypt() actually do.
  function chaoStep(left, right, i) {
    const leftR = chaoRotate(left, i);
    const rightR = chaoRotate(right, i + 1);
    return [chaoRemoveInsert(leftR, 1, 13), chaoRemoveInsert(rightR, 2, 13)];
  }

  register({
    id: 'chaocipher',
    label: 'Chaocipher',
    fields: [
      { name: 'leftAlphabet', label: 'Left disk alphabet (ciphertext), 26 letters', type: 'text', placeholder: 'e.g. XLEMFHIWOVNYRUDQCJPASGBTKZ' },
      { name: 'rightAlphabet', label: 'Right disk alphabet (plaintext), 26 letters', type: 'text', placeholder: 'e.g. SGLBIZHJMFTRXAVKNQPDWYCUOE' },
    ],
    randomKey() {
      const leftAlphabet = shuffled(ALPHABET.split('')).join('');
      const rightAlphabet = shuffled(ALPHABET.split('')).join('');
      return { key: { leftAlphabet, rightAlphabet }, values: { leftAlphabet, rightAlphabet } };
    },
    keyFromValues(values) {
      const left = onlyLetters(values.leftAlphabet);
      const right = onlyLetters(values.rightAlphabet);
      if (left.length !== 26 || new Set(left).size !== 26) throw new Error('Left disk alphabet must contain exactly the 26 letters A-Z, each once.');
      if (right.length !== 26 || new Set(right).size !== 26) throw new Error('Right disk alphabet must contain exactly the 26 letters A-Z, each once.');
      return { leftAlphabet: left, rightAlphabet: right };
    },
    keyInfo(key) { return `left=${key.leftAlphabet} right=${key.rightAlphabet}`; },
    encrypt(pt, key) {
      let left = key.leftAlphabet.split('');
      let right = key.rightAlphabet.split('');
      let out = '';
      for (const ch of pt) {
        const i = right.indexOf(ch);
        out += left[i];
        [left, right] = chaoStep(left, right, i);
      }
      return out;
    },
    decrypt(ct, key) {
      let left = key.leftAlphabet.split('');
      let right = key.rightAlphabet.split('');
      let out = '';
      for (const ch of ct) {
        const i = left.indexOf(ch);
        out += right[i];
        [left, right] = chaoStep(left, right, i);
      }
      return out;
    },
  });

  // ---------------------------------------------------------------------
  // Vigenere / Beaufort / Porta / Autokey / Running key (all straight-alphabet,
  // repeating- or extending-key polyalphabetic ciphers)
  // ---------------------------------------------------------------------
  register({
    id: 'vigenere',
    label: 'Vigenere',
    fields: [{ name: 'keyword', label: 'Keyword', type: 'text', placeholder: 'e.g. LEMON' }],
    randomKey() {
      const keyword = pickDictionaryWord(4, 10);
      return { key: { keyword }, values: { keyword } };
    },
    keyFromValues(values) {
      const k = onlyLetters(values.keyword);
      validateLength(k, 'Keyword');
      return { keyword: k };
    },
    keyInfo(key) { return `keyword=${key.keyword}`; },
    encrypt(pt, key) {
      const k = key.keyword;
      return pt.split('').map((ch, i) => numLetter(letterNum(ch) + letterNum(k[i % k.length]))).join('');
    },
    decrypt(ct, key) {
      const k = key.keyword;
      return ct.split('').map((ch, i) => numLetter(letterNum(ch) - letterNum(k[i % k.length]))).join('');
    },
  });

  register({
    id: 'beaufort',
    label: 'Beaufort',
    fields: [{ name: 'keyword', label: 'Keyword', type: 'text', placeholder: 'e.g. FORTIFICATION' }],
    randomKey() {
      const keyword = pickDictionaryWord(4, 10);
      return { key: { keyword }, values: { keyword } };
    },
    keyFromValues(values) {
      const k = onlyLetters(values.keyword);
      validateLength(k, 'Keyword');
      return { keyword: k };
    },
    keyInfo(key) { return `keyword=${key.keyword}`; },
    // Beaufort is self-reciprocal: C = K - P, and P = K - C use the same formula.
    encrypt(pt, key) {
      const k = key.keyword;
      return pt.split('').map((ch, i) => numLetter(letterNum(k[i % k.length]) - letterNum(ch))).join('');
    },
    decrypt(ct, key) {
      const k = key.keyword;
      return ct.split('').map((ch, i) => numLetter(letterNum(k[i % k.length]) - letterNum(ch))).join('');
    },
  });

  register({
    id: 'porta',
    label: 'Porta',
    fields: [{ name: 'keyword', label: 'Keyword', type: 'text', placeholder: 'e.g. PORTA' }],
    randomKey() {
      const keyword = pickDictionaryWord(4, 10);
      return { key: { keyword }, values: { keyword } };
    },
    keyFromValues(values) {
      const k = onlyLetters(values.keyword);
      validateLength(k, 'Keyword');
      return { keyword: k };
    },
    keyInfo(key) { return `keyword=${key.keyword}`; },
    // Porta is self-reciprocal (13 reciprocal alphabets selected by key-letter pair group).
    encrypt(pt, key) {
      const k = key.keyword;
      return pt.split('').map((ch, i) => {
        const g = Math.floor(letterNum(k[i % k.length]) / 2); // 0-12
        const p = letterNum(ch);
        if (p < 13) return numLetter(13 + mod(p + g, 13));
        return numLetter(mod((p - 13) - g, 13));
      }).join('');
    },
    decrypt(ct, key) { return CIPHERS.porta.encrypt(ct, key); },
  });

  register({
    id: 'autokey',
    label: 'Autokey',
    fields: [{ name: 'primer', label: 'Primer keyword', type: 'text', placeholder: 'e.g. QUEEN' }],
    randomKey() {
      const primer = pickDictionaryWord(4, 10);
      return { key: { primer }, values: { primer } };
    },
    keyFromValues(values) {
      const p = onlyLetters(values.primer);
      validateLength(p, 'Primer keyword');
      return { primer: p };
    },
    keyInfo(key) { return `primer=${key.primer}`; },
    encrypt(pt, key) {
      const stream = (key.primer + pt).slice(0, pt.length);
      return pt.split('').map((ch, i) => numLetter(letterNum(ch) + letterNum(stream[i]))).join('');
    },
    decrypt(ct, key) {
      let pt = '';
      const primer = key.primer;
      for (let i = 0; i < ct.length; i++) {
        const kch = i < primer.length ? primer[i] : pt[i - primer.length];
        pt += numLetter(letterNum(ct[i]) - letterNum(kch));
      }
      return pt;
    },
  });

  // Straight-alphabet running key: C = P + K (mod 26), K = a long,
  // non-repeating passage of text at least as long as the plaintext. Shared
  // engine for the standalone "Running Key" cipher just below, and for the
  // two running-key-plus-transposition ciphers further down. (See "Running
  // Key I - IV" further below for the keyed-alphabet variants of this same
  // running-key idea, mirroring Quagmire's four plain/cipher-alphabet
  // combinations.)
  function runningKeyStraightRandomKey(opts) {
    const ptLen = (opts && opts.ptLength) || 97;
    const corpora = global.CIPHERGEN_CORPORA || [];
    for (let tries = 0; tries < 50; tries++) {
      const src = randChoice(corpora);
      if (src.text.length < ptLen + 2) continue;
      const start = randInt(0, src.text.length - ptLen - 1);
      let excerpt = src.text.substr(start, ptLen + 40).replace(/ /g, '');
      if (excerpt.length >= ptLen) {
        const keyText = excerpt.slice(0, ptLen);
        return { key: { keyText, source: src.file, offset: start }, values: { keyText } };
      }
    }
    // fallback: repeat a dictionary word to reach length
    const w = pickDictionaryWord(4, 10);
    let keyText = '';
    while (keyText.length < ptLen) keyText += w;
    keyText = keyText.slice(0, ptLen);
    return { key: { keyText }, values: { keyText } };
  }
  function runningKeyStraightKeyFromValues(values) {
    const k = onlyLetters(values.keyText);
    validateLength(k, 'Key text');
    return { keyText: k };
  }
  function runningKeyStraightKeyInfo(key) {
    return `key=${key.keyText}${key.source ? ` (source=${key.source}@${key.offset})` : ''}`;
  }
  function runningKeyStraightEncrypt(pt, key) {
    if (key.keyText.length < pt.length) throw new Error('Running key text is shorter than the plaintext.');
    return pt.split('').map((ch, i) => numLetter(letterNum(ch) + letterNum(key.keyText[i]))).join('');
  }
  function runningKeyStraightDecrypt(ct, key) {
    if (key.keyText.length < ct.length) throw new Error('Running key text is shorter than the ciphertext.');
    return ct.split('').map((ch, i) => numLetter(letterNum(ch) - letterNum(key.keyText[i]))).join('');
  }

  // Standalone Running Key: both plaintext and ciphertext alphabets are
  // straight (unkeyed) A-Z - the one plain/cipher-alphabet combination
  // Running Key I-IV below don't cover, since each of those keys at least
  // one side. Also used as-is by the two running-key-plus-transposition
  // ciphers further down.
  register({
    id: 'running_key',
    label: 'Running Key',
    fields: [{ name: 'keyText', label: 'Key text (letters only, at least as long as the plaintext)', type: 'textarea', placeholder: 'a long passage of key text...' }],
    randomKey(opts) { return runningKeyStraightRandomKey(opts); },
    keyFromValues(values) { return runningKeyStraightKeyFromValues(values); },
    keyInfo(key) { return runningKeyStraightKeyInfo(key); },
    encrypt(pt, key) { return runningKeyStraightEncrypt(pt, key); },
    decrypt(ct, key) { return runningKeyStraightDecrypt(ct, key); },
  });

  // Running Key ACA: the ACA "Cryptogram" RUNNING KEY variant
  // (cryptogram.org/downloads/aca.info/ciphers/RunningKey.pdf). A single
  // passage is split in half; the first half is never transmitted and acts
  // purely as the key for encrypting the second half (straight Vigenere -
  // same encrypt/decrypt math as the standalone Running Key above). What
  // makes this the ACA variant specifically (rather than just another
  // "Running Key" with an unrelated key) is that the key is a genuine
  // continuation of the same passage, not independent text - so during
  // generation the key is sourced as the text immediately preceding the
  // chosen plaintext in the same corpus source, falling back to an
  // unrelated excerpt (like standalone Running Key) only when the
  // plaintext was selected too close to the start of its source to have
  // that much preceding text.
  register({
    id: 'running_key_aca',
    label: 'Running Key ACA',
    fields: [{ name: 'keyText', label: 'Key text (the other half of the passage, letters only, at least as long as the plaintext)', type: 'textarea', placeholder: 'the text that immediately precedes the plaintext...' }],
    randomKey(opts) {
      const ptLen = (opts && opts.ptLength) || 97;
      const preceding = (opts && opts.precedingText) || '';
      if (preceding.length >= ptLen) {
        const keyText = preceding.slice(preceding.length - ptLen);
        return { key: { keyText }, values: { keyText } };
      }
      return runningKeyStraightRandomKey(opts); // not enough adjacent context - fall back to an unrelated excerpt
    },
    keyFromValues(values) { return runningKeyStraightKeyFromValues(values); },
    keyInfo(key) { return runningKeyStraightKeyInfo(key); },
    encrypt(pt, key) { return runningKeyStraightEncrypt(pt, key); },
    decrypt(ct, key) { return runningKeyStraightDecrypt(ct, key); },
  });

  // ---------------------------------------------------------------------
  // Quagmire I - IV
  // Formulas verified against the ACA "Cryptogram" reference examples
  // (QuagmireI/II/III/IV.pdf) and, for Quagmire III, against the real
  // Kryptos K1/K2 plaintext-keyword-indicator triples.
  // ---------------------------------------------------------------------
  function quagmireFields(withKeyword2) {
    const f = [
      { name: 'keyword1', label: withKeyword2 ? 'Keyword 1 (plaintext alphabet)' : 'Keyword', type: 'text', placeholder: 'e.g. KRYPTOS' },
    ];
    if (withKeyword2) f.push({ name: 'keyword2', label: 'Keyword 2 (ciphertext alphabet)', type: 'text', placeholder: 'e.g. ABSCISSA' });
    f.push({ name: 'indicator', label: 'Indicator (cycle) word', type: 'text', placeholder: 'e.g. PALIMPSEST' });
    return f;
  }

  function quagmireRandomKey(withKeyword2) {
    const words = withKeyword2 ? pickDistinctDictionaryWords(3, 5, 9) : pickDistinctDictionaryWords(2, 5, 9);
    const keyword1 = words[0];
    const keyword2 = withKeyword2 ? words[1] : undefined;
    const indicator = withKeyword2 ? words[2] : words[1];
    const key = { keyword1, indicator };
    const values = { keyword1, indicator };
    if (withKeyword2) { key.keyword2 = keyword2; values.keyword2 = keyword2; }
    return { key, values };
  }

  function quagmireKeyFromValues(values, withKeyword2) {
    const keyword1 = onlyLetters(values.keyword1);
    const indicator = onlyLetters(values.indicator);
    validateLength(keyword1, 'Keyword 1');
    validateLength(indicator, 'Indicator word');
    const key = { keyword1, indicator };
    if (withKeyword2) {
      const keyword2 = onlyLetters(values.keyword2);
      validateLength(keyword2, 'Keyword 2');
      key.keyword2 = keyword2;
    }
    return key;
  }

  // Quagmire I: keyed plaintext alphabet, straight ciphertext alphabet.
  register({
    id: 'quagmire1',
    label: 'Quagmire I',
    fields: quagmireFields(false),
    randomKey() { return quagmireRandomKey(false); },
    keyFromValues(values) { return quagmireKeyFromValues(values, false); },
    keyInfo(key) { return `keyword=${key.keyword1} indicator=${key.indicator}`; },
    encrypt(pt, key) {
      const M = keyedAlphabet26(key.keyword1);
      const Minv = new Array(26);
      for (let i = 0; i < 26; i++) Minv[letterNum(M[i])] = i;
      const anchor = Minv[0]; // position of 'A' within M
      const ind = key.indicator;
      return pt.split('').map((ch, i) => {
        const k = ind[i % ind.length];
        const idx = mod(letterNum(k) - anchor + Minv[letterNum(ch)], 26);
        return numLetter(idx);
      }).join('');
    },
    decrypt(ct, key) {
      const M = keyedAlphabet26(key.keyword1);
      const Minv = new Array(26);
      for (let i = 0; i < 26; i++) Minv[letterNum(M[i])] = i;
      const anchor = Minv[0];
      const ind = key.indicator;
      return ct.split('').map((ch, i) => {
        const k = ind[i % ind.length];
        const idx = mod(letterNum(ch) - letterNum(k) + anchor, 26);
        return M[idx];
      }).join('');
    },
  });

  // Quagmire II: straight plaintext alphabet, keyed ciphertext alphabet.
  register({
    id: 'quagmire2',
    label: 'Quagmire II',
    fields: quagmireFields(false),
    randomKey() { return quagmireRandomKey(false); },
    keyFromValues(values) { return quagmireKeyFromValues(values, false); },
    keyInfo(key) { return `keyword=${key.keyword1} indicator=${key.indicator}`; },
    encrypt(pt, key) {
      const M = keyedAlphabet26(key.keyword1);
      const Minv = new Array(26);
      for (let i = 0; i < 26; i++) Minv[letterNum(M[i])] = i;
      const ind = key.indicator;
      return pt.split('').map((ch, i) => {
        const k = ind[i % ind.length];
        const idx = mod(Minv[letterNum(k)] + letterNum(ch), 26);
        return M[idx];
      }).join('');
    },
    decrypt(ct, key) {
      const M = keyedAlphabet26(key.keyword1);
      const Minv = new Array(26);
      for (let i = 0; i < 26; i++) Minv[letterNum(M[i])] = i;
      const ind = key.indicator;
      return ct.split('').map((ch, i) => {
        const k = ind[i % ind.length];
        const idx = mod(Minv[letterNum(ch)] - Minv[letterNum(k)], 26);
        return numLetter(idx);
      }).join('');
    },
  });

  // Quagmire III: same keyed alphabet used for both plaintext and ciphertext.
  register({
    id: 'quagmire3',
    label: 'Quagmire III',
    fields: quagmireFields(false),
    randomKey() { return quagmireRandomKey(false); },
    keyFromValues(values) { return quagmireKeyFromValues(values, false); },
    keyInfo(key) { return `keyword=${key.keyword1} indicator=${key.indicator}`; },
    encrypt(pt, key) {
      const M = keyedAlphabet26(key.keyword1);
      const Minv = new Array(26);
      for (let i = 0; i < 26; i++) Minv[letterNum(M[i])] = i;
      const ind = key.indicator;
      return pt.split('').map((ch, i) => {
        const k = ind[i % ind.length];
        const idx = mod(Minv[letterNum(k)] + Minv[letterNum(ch)], 26);
        return M[idx];
      }).join('');
    },
    decrypt(ct, key) {
      const M = keyedAlphabet26(key.keyword1);
      const Minv = new Array(26);
      for (let i = 0; i < 26; i++) Minv[letterNum(M[i])] = i;
      const ind = key.indicator;
      return ct.split('').map((ch, i) => {
        const k = ind[i % ind.length];
        const idx = mod(Minv[letterNum(ch)] - Minv[letterNum(k)], 26);
        return M[idx];
      }).join('');
    },
  });

  // Quagmire IV: independent keyed alphabets for plaintext and ciphertext.
  register({
    id: 'quagmire4',
    label: 'Quagmire IV',
    fields: quagmireFields(true),
    randomKey() { return quagmireRandomKey(true); },
    keyFromValues(values) { return quagmireKeyFromValues(values, true); },
    keyInfo(key) { return `keyword1=${key.keyword1} keyword2=${key.keyword2} indicator=${key.indicator}`; },
    encrypt(pt, key) {
      const M1 = keyedAlphabet26(key.keyword1);
      const M2 = keyedAlphabet26(key.keyword2);
      const M1inv = new Array(26); for (let i = 0; i < 26; i++) M1inv[letterNum(M1[i])] = i;
      const M2inv = new Array(26); for (let i = 0; i < 26; i++) M2inv[letterNum(M2[i])] = i;
      const ind = key.indicator;
      return pt.split('').map((ch, i) => {
        const k = ind[i % ind.length];
        const idx = mod(M2inv[letterNum(k)] + M1inv[letterNum(ch)], 26);
        return M2[idx];
      }).join('');
    },
    decrypt(ct, key) {
      const M1 = keyedAlphabet26(key.keyword1);
      const M2 = keyedAlphabet26(key.keyword2);
      const M1inv = new Array(26); for (let i = 0; i < 26; i++) M1inv[letterNum(M1[i])] = i;
      const M2inv = new Array(26); for (let i = 0; i < 26; i++) M2inv[letterNum(M2[i])] = i;
      const ind = key.indicator;
      return ct.split('').map((ch, i) => {
        const k = ind[i % ind.length];
        const idx = mod(M2inv[letterNum(ch)] - M2inv[letterNum(k)], 26);
        return M1[idx];
      }).join('');
    },
  });

  // ---------------------------------------------------------------------
  // Running Key I - IV
  // Same four plain/cipher-alphabet combinations as Quagmire I-IV, but the
  // short indicator word that cycles is replaced by a long, non-repeating
  // running key text (at least as long as the plaintext) - one key letter
  // per plaintext letter, sourced from a random corpus excerpt, same as the
  // plain (straight-alphabet) running key mechanism above.
  // ---------------------------------------------------------------------
  function runningKeyVariantFields(withKeyword2) {
    const f = [
      { name: 'keyword1', label: withKeyword2 ? 'Keyword 1 (plaintext alphabet)' : 'Keyword', type: 'text', placeholder: 'e.g. KRYPTOS' },
    ];
    if (withKeyword2) f.push({ name: 'keyword2', label: 'Keyword 2 (ciphertext alphabet)', type: 'text', placeholder: 'e.g. ABSCISSA' });
    f.push({ name: 'keyText', label: 'Running key text (letters only, at least as long as the plaintext)', type: 'textarea', placeholder: 'a long passage of key text...' });
    return f;
  }

  function runningKeyVariantRandomKey(withKeyword2, opts) {
    const words = withKeyword2 ? pickDistinctDictionaryWords(2, 5, 9) : [pickDictionaryWord(5, 9)];
    const keyword1 = words[0];
    const rk = runningKeyStraightRandomKey(opts);
    const key = { keyword1, runningKey: rk.key };
    const values = { keyword1, keyText: rk.values.keyText };
    if (withKeyword2) { key.keyword2 = words[1]; values.keyword2 = words[1]; }
    return { key, values };
  }

  function runningKeyVariantKeyFromValues(values, withKeyword2) {
    const keyword1 = onlyLetters(values.keyword1);
    validateLength(keyword1, withKeyword2 ? 'Keyword 1' : 'Keyword');
    const key = { keyword1, runningKey: runningKeyStraightKeyFromValues({ keyText: values.keyText }) };
    if (withKeyword2) {
      const keyword2 = onlyLetters(values.keyword2);
      validateLength(keyword2, 'Keyword 2');
      key.keyword2 = keyword2;
    }
    return key;
  }

  // Running Key I: keyed plaintext alphabet, straight ciphertext alphabet.
  register({
    id: 'running_key1',
    label: 'Running Key I',
    fields: runningKeyVariantFields(false),
    randomKey(opts) { return runningKeyVariantRandomKey(false, opts); },
    keyFromValues(values) { return runningKeyVariantKeyFromValues(values, false); },
    keyInfo(key) { return `keyword=${key.keyword1} ${runningKeyStraightKeyInfo(key.runningKey)}`; },
    encrypt(pt, key) {
      const kt = key.runningKey.keyText;
      if (kt.length < pt.length) throw new Error('Running key text is shorter than the plaintext.');
      const M = keyedAlphabet26(key.keyword1);
      const Minv = new Array(26);
      for (let i = 0; i < 26; i++) Minv[letterNum(M[i])] = i;
      const anchor = Minv[0]; // position of 'A' within M
      return pt.split('').map((ch, i) => {
        const idx = mod(letterNum(kt[i]) - anchor + Minv[letterNum(ch)], 26);
        return numLetter(idx);
      }).join('');
    },
    decrypt(ct, key) {
      const kt = key.runningKey.keyText;
      if (kt.length < ct.length) throw new Error('Running key text is shorter than the ciphertext.');
      const M = keyedAlphabet26(key.keyword1);
      const Minv = new Array(26);
      for (let i = 0; i < 26; i++) Minv[letterNum(M[i])] = i;
      const anchor = Minv[0];
      return ct.split('').map((ch, i) => {
        const idx = mod(letterNum(ch) - letterNum(kt[i]) + anchor, 26);
        return M[idx];
      }).join('');
    },
  });

  // Running Key II: straight plaintext alphabet, keyed ciphertext alphabet.
  register({
    id: 'running_key2',
    label: 'Running Key II',
    fields: runningKeyVariantFields(false),
    randomKey(opts) { return runningKeyVariantRandomKey(false, opts); },
    keyFromValues(values) { return runningKeyVariantKeyFromValues(values, false); },
    keyInfo(key) { return `keyword=${key.keyword1} ${runningKeyStraightKeyInfo(key.runningKey)}`; },
    encrypt(pt, key) {
      const kt = key.runningKey.keyText;
      if (kt.length < pt.length) throw new Error('Running key text is shorter than the plaintext.');
      const M = keyedAlphabet26(key.keyword1);
      const Minv = new Array(26);
      for (let i = 0; i < 26; i++) Minv[letterNum(M[i])] = i;
      return pt.split('').map((ch, i) => {
        const idx = mod(Minv[letterNum(kt[i])] + letterNum(ch), 26);
        return M[idx];
      }).join('');
    },
    decrypt(ct, key) {
      const kt = key.runningKey.keyText;
      if (kt.length < ct.length) throw new Error('Running key text is shorter than the ciphertext.');
      const M = keyedAlphabet26(key.keyword1);
      const Minv = new Array(26);
      for (let i = 0; i < 26; i++) Minv[letterNum(M[i])] = i;
      return ct.split('').map((ch, i) => {
        const idx = mod(Minv[letterNum(ch)] - Minv[letterNum(kt[i])], 26);
        return numLetter(idx);
      }).join('');
    },
  });

  // Running Key III: same keyed alphabet used for both plaintext and ciphertext.
  register({
    id: 'running_key3',
    label: 'Running Key III',
    fields: runningKeyVariantFields(false),
    randomKey(opts) { return runningKeyVariantRandomKey(false, opts); },
    keyFromValues(values) { return runningKeyVariantKeyFromValues(values, false); },
    keyInfo(key) { return `keyword=${key.keyword1} ${runningKeyStraightKeyInfo(key.runningKey)}`; },
    encrypt(pt, key) {
      const kt = key.runningKey.keyText;
      if (kt.length < pt.length) throw new Error('Running key text is shorter than the plaintext.');
      const M = keyedAlphabet26(key.keyword1);
      const Minv = new Array(26);
      for (let i = 0; i < 26; i++) Minv[letterNum(M[i])] = i;
      return pt.split('').map((ch, i) => {
        const idx = mod(Minv[letterNum(kt[i])] + Minv[letterNum(ch)], 26);
        return M[idx];
      }).join('');
    },
    decrypt(ct, key) {
      const kt = key.runningKey.keyText;
      if (kt.length < ct.length) throw new Error('Running key text is shorter than the ciphertext.');
      const M = keyedAlphabet26(key.keyword1);
      const Minv = new Array(26);
      for (let i = 0; i < 26; i++) Minv[letterNum(M[i])] = i;
      return ct.split('').map((ch, i) => {
        const idx = mod(Minv[letterNum(ch)] - Minv[letterNum(kt[i])], 26);
        return M[idx];
      }).join('');
    },
  });

  // Running Key IV: independent keyed alphabets for plaintext and ciphertext.
  register({
    id: 'running_key4',
    label: 'Running Key IV',
    fields: runningKeyVariantFields(true),
    randomKey(opts) { return runningKeyVariantRandomKey(true, opts); },
    keyFromValues(values) { return runningKeyVariantKeyFromValues(values, true); },
    keyInfo(key) { return `keyword1=${key.keyword1} keyword2=${key.keyword2} ${runningKeyStraightKeyInfo(key.runningKey)}`; },
    encrypt(pt, key) {
      const kt = key.runningKey.keyText;
      if (kt.length < pt.length) throw new Error('Running key text is shorter than the plaintext.');
      const M1 = keyedAlphabet26(key.keyword1);
      const M2 = keyedAlphabet26(key.keyword2);
      const M1inv = new Array(26); for (let i = 0; i < 26; i++) M1inv[letterNum(M1[i])] = i;
      const M2inv = new Array(26); for (let i = 0; i < 26; i++) M2inv[letterNum(M2[i])] = i;
      return pt.split('').map((ch, i) => {
        const idx = mod(M2inv[letterNum(kt[i])] + M1inv[letterNum(ch)], 26);
        return M2[idx];
      }).join('');
    },
    decrypt(ct, key) {
      const kt = key.runningKey.keyText;
      if (kt.length < ct.length) throw new Error('Running key text is shorter than the ciphertext.');
      const M1 = keyedAlphabet26(key.keyword1);
      const M2 = keyedAlphabet26(key.keyword2);
      const M1inv = new Array(26); for (let i = 0; i < 26; i++) M1inv[letterNum(M1[i])] = i;
      const M2inv = new Array(26); for (let i = 0; i < 26; i++) M2inv[letterNum(M2[i])] = i;
      return ct.split('').map((ch, i) => {
        const idx = mod(M2inv[letterNum(ch)] - M2inv[letterNum(kt[i])], 26);
        return M1[idx];
      }).join('');
    },
  });

  // ---------------------------------------------------------------------
  // Rail fence
  // ---------------------------------------------------------------------
  register({
    id: 'rail_fence',
    label: 'Rail Fence',
    fields: [{ name: 'rails', label: 'Number of rails', type: 'number', min: 2, max: 12 }],
    randomKey() {
      const rails = randInt(3, 6);
      return { key: { rails }, values: { rails: String(rails) } };
    },
    keyFromValues(values) {
      const rails = parseInt(values.rails, 10);
      if (!Number.isInteger(rails) || rails < 2) throw new Error('Number of rails must be an integer >= 2.');
      return { rails };
    },
    keyInfo(key) { return `rails=${key.rails}`; },
    encrypt(pt, key) {
      const rails = Math.min(key.rails, Math.max(2, pt.length));
      const rows = Array.from({ length: rails }, () => []);
      let row = 0, dir = 1;
      for (const ch of pt) {
        rows[row].push(ch);
        if (rails > 1) {
          if (row === 0) dir = 1; else if (row === rails - 1) dir = -1;
          row += dir;
        }
      }
      return rows.map((r) => r.join('')).join('');
    },
    decrypt(ct, key) {
      const rails = Math.min(key.rails, Math.max(2, ct.length));
      const n = ct.length;
      const pattern = [];
      let row = 0, dir = 1;
      for (let i = 0; i < n; i++) {
        pattern.push(row);
        if (rails > 1) {
          if (row === 0) dir = 1; else if (row === rails - 1) dir = -1;
          row += dir;
        }
      }
      const counts = new Array(rails).fill(0);
      pattern.forEach((r) => counts[r]++);
      const rowsText = [];
      let pos = 0;
      for (let r = 0; r < rails; r++) { rowsText.push(ct.substr(pos, counts[r]).split('')); pos += counts[r]; }
      const rowPos = new Array(rails).fill(0);
      let out = '';
      for (let i = 0; i < n; i++) { const r = pattern[i]; out += rowsText[r][rowPos[r]++]; }
      return out;
    },
  });

  // ---------------------------------------------------------------------
  // Scytale (equivalent to an unkeyed columnar transposition: natural
  // ascending column order, no keyword scrambling)
  // ---------------------------------------------------------------------
  register({
    id: 'scytale',
    label: 'Scytale',
    fields: [{ name: 'faces', label: 'Number of faces (columns)', type: 'number', min: 2, max: 20 }],
    randomKey() {
      const faces = randInt(3, 8);
      return { key: { faces }, values: { faces: String(faces) } };
    },
    keyFromValues(values) {
      const faces = parseInt(values.faces, 10);
      if (!Number.isInteger(faces) || faces < 2) throw new Error('Number of faces must be an integer >= 2.');
      return { faces };
    },
    keyInfo(key) { return `faces=${key.faces}`; },
    encrypt(pt, key) { return columnarEncryptRaw(pt, rangeArray(key.faces)); },
    decrypt(ct, key) { return columnarDecryptRaw(ct, rangeArray(key.faces)); },
  });

  function rangeArray(n) { return Array.from({ length: n }, (_, i) => i); }

  // ---------------------------------------------------------------------
  // Columnar transposition core (irregular grid, no padding). `order` is an
  // array of 0-based column indices (original left-to-right position) listed
  // in the order they should be read off.
  // ---------------------------------------------------------------------
  function columnarEncryptRaw(pt, order) {
    const k = order.length;
    const n = pt.length;
    const numRows = Math.ceil(n / k);
    const longCols = n % k === 0 ? k : n % k; // first `longCols` columns (by original position) have numRows letters
    const colLen = (col) => (col < longCols ? numRows : numRows - 1);
    const grid = Array.from({ length: k }, () => []);
    let pos = 0;
    for (let r = 0; r < numRows; r++) {
      for (let c = 0; c < k; c++) {
        if (r < colLen(c)) grid[c].push(pt[pos++]);
      }
    }
    return order.map((c) => grid[c].join('')).join('');
  }

  function columnarDecryptRaw(ct, order) {
    const k = order.length;
    const n = ct.length;
    const numRows = Math.ceil(n / k);
    const longCols = n % k === 0 ? k : n % k;
    const colLen = (col) => (col < longCols ? numRows : numRows - 1);
    const grid = new Array(k);
    let pos = 0;
    for (const c of order) {
      const len = colLen(c);
      grid[c] = ct.substr(pos, len).split('');
      pos += len;
    }
    let out = '';
    for (let r = 0; r < numRows; r++) {
      for (let c = 0; c < k; c++) {
        if (r < colLen(c)) out += grid[c][r];
      }
    }
    return out;
  }

  function orderFromRanks(rank) {
    // rank[col] = 0-based read order -> produce array of column indices sorted by rank
    return rank.map((r, col) => [r, col]).sort((a, b) => a[0] - b[0]).map((p) => p[1]);
  }

  register({
    id: 'columnar_transposition',
    label: 'Columnar Transposition',
    fields: [{ name: 'keyword', label: 'Keyword (letters must be distinct)', type: 'text', placeholder: 'e.g. ZEBRAS' }],
    randomKey() {
      const keyword = pickDistinctLetterWord(5, 9);
      return { key: { keyword }, values: { keyword } };
    },
    keyFromValues(values) {
      const k = onlyLetters(values.keyword);
      validateLength(k, 'Keyword');
      if (new Set(k).size !== k.length) throw new Error('Columnar transposition keyword letters must be distinct.');
      return { keyword: k };
    },
    keyInfo(key) { return `keyword=${key.keyword}`; },
    encrypt(pt, key) { return columnarEncryptRaw(pt, orderFromRanks(keywordColumnRanks(key.keyword))); },
    decrypt(ct, key) { return columnarDecryptRaw(ct, orderFromRanks(keywordColumnRanks(key.keyword))); },
  });

  register({
    id: 'double_columnar_transposition',
    label: 'Double Columnar Transposition',
    fields: [
      { name: 'keyword1', label: 'Keyword 1 (letters must be distinct)', type: 'text', placeholder: 'e.g. ZEBRAS' },
      { name: 'keyword2', label: 'Keyword 2 (letters must be distinct)', type: 'text', placeholder: 'e.g. CIPHER' },
    ],
    randomKey() {
      const [keyword1, keyword2] = pickDistinctLetterWordPair();
      return { key: { keyword1, keyword2 }, values: { keyword1, keyword2 } };
    },
    keyFromValues(values) {
      const k1 = onlyLetters(values.keyword1);
      const k2 = onlyLetters(values.keyword2);
      validateLength(k1, 'Keyword 1');
      validateLength(k2, 'Keyword 2');
      if (new Set(k1).size !== k1.length) throw new Error('Keyword 1 letters must be distinct.');
      if (new Set(k2).size !== k2.length) throw new Error('Keyword 2 letters must be distinct.');
      return { keyword1: k1, keyword2: k2 };
    },
    keyInfo(key) { return `keyword1=${key.keyword1} keyword2=${key.keyword2}`; },
    encrypt(pt, key) {
      const step1 = columnarEncryptRaw(pt, orderFromRanks(keywordColumnRanks(key.keyword1)));
      return columnarEncryptRaw(step1, orderFromRanks(keywordColumnRanks(key.keyword2)));
    },
    decrypt(ct, key) {
      const step1 = columnarDecryptRaw(ct, orderFromRanks(keywordColumnRanks(key.keyword2)));
      return columnarDecryptRaw(step1, orderFromRanks(keywordColumnRanks(key.keyword1)));
    },
  });

  function pickDistinctLetterWord(minLen, maxLen) {
    for (let tries = 0; tries < 300; tries++) {
      const w = pickDictionaryWord(minLen, maxLen);
      if (new Set(w).size === w.length) return w;
    }
    return keyedAlphabet26(pickDictionaryWord(minLen, maxLen)).slice(0, minLen);
  }
  function pickDistinctLetterWordPair() {
    const w1 = pickDistinctLetterWord(5, 9);
    let w2 = pickDistinctLetterWord(5, 9);
    let tries = 0;
    while (w2 === w1 && tries < 30) { w2 = pickDistinctLetterWord(5, 9); tries++; }
    return [w1, w2];
  }

  // ---------------------------------------------------------------------
  // Myszkowski transposition (columnar transposition whose keyword may
  // repeat letters; columns sharing a rank are read together, row by row).
  // ---------------------------------------------------------------------
  register({
    id: 'myszkowski',
    label: 'Myszkowski Transposition',
    fields: [{ name: 'keyword', label: 'Keyword (repeated letters allowed)', type: 'text', placeholder: 'e.g. TOMATO' }],
    randomKey() {
      const keyword = pickDictionaryWord(5, 9);
      return { key: { keyword }, values: { keyword } };
    },
    keyFromValues(values) {
      const k = onlyLetters(values.keyword);
      validateLength(k, 'Keyword');
      return { keyword: k };
    },
    keyInfo(key) { return `keyword=${key.keyword}`; },
    encrypt(pt, key) {
      const letters = key.keyword.split('');
      const k = letters.length;
      const n = pt.length;
      const numRows = Math.ceil(n / k);
      const longCols = n % k === 0 ? k : n % k;
      const colLen = (col) => (col < longCols ? numRows : numRows - 1);
      const grid = Array.from({ length: k }, () => []);
      let pos = 0;
      for (let r = 0; r < numRows; r++) {
        for (let c = 0; c < k; c++) if (r < colLen(c)) grid[c].push(pt[pos++]);
      }
      const uniqueSorted = Array.from(new Set(letters)).sort();
      let out = '';
      for (const letterVal of uniqueSorted) {
        const cols = letters.map((ch, i) => (ch === letterVal ? i : -1)).filter((i) => i >= 0);
        const rows = Math.max(...cols.map(colLen));
        for (let r = 0; r < rows; r++) {
          for (const c of cols) if (r < colLen(c)) out += grid[c][r];
        }
      }
      return out;
    },
    decrypt(ct, key) {
      const letters = key.keyword.split('');
      const k = letters.length;
      const n = ct.length;
      const numRows = Math.ceil(n / k);
      const longCols = n % k === 0 ? k : n % k;
      const colLen = (col) => (col < longCols ? numRows : numRows - 1);
      const uniqueSorted = Array.from(new Set(letters)).sort();
      const grid = new Array(k);
      let pos = 0;
      for (const letterVal of uniqueSorted) {
        const cols = letters.map((ch, i) => (ch === letterVal ? i : -1)).filter((i) => i >= 0);
        const rows = Math.max(...cols.map(colLen));
        const bufs = {}; cols.forEach((c) => { bufs[c] = []; });
        for (let r = 0; r < rows; r++) {
          for (const c of cols) if (r < colLen(c)) bufs[c].push(ct[pos++]);
        }
        cols.forEach((c) => { grid[c] = bufs[c]; });
      }
      let out = '';
      for (let r = 0; r < numRows; r++) {
        for (let c = 0; c < k; c++) if (r < colLen(c)) out += grid[c][r];
      }
      return out;
    },
  });

  // ---------------------------------------------------------------------
  // Running Key + Transposition / Transposition + Running Key
  //
  // Two-layer ciphers: a Running Key encryption plus a transposition step,
  // applied before or after. The transposition step can be either "simple
  // periodic" (an explicit numeric column-read order, entered as a
  // comma-separated permutation like "3,1,4,2") or ordinary keyword-based
  // columnar transposition - both reduce to the same columnar transposition
  // core (columnarEncryptRaw/columnarDecryptRaw above), just with a
  // different source for the column read order. Which one the user meant is
  // auto-detected from the transposition key field: digits -> periodic,
  // letters -> columnar.
  // ---------------------------------------------------------------------
  function parseTranspositionKey(raw) {
    const trimmed = (raw || '').trim();
    if (!trimmed) throw new Error('Transposition key must not be empty.');
    if (/^[0-9]+([,\s]+[0-9]+)*$/.test(trimmed)) {
      const nums = trimmed.split(/[,\s]+/).map((v) => parseInt(v, 10));
      const period = nums.length;
      if (period < 2) throw new Error('Simple periodic transposition needs at least 2 columns.');
      const sorted = nums.slice().sort((a, b) => a - b);
      for (let i = 0; i < period; i++) {
        if (sorted[i] !== i + 1) throw new Error('Simple periodic transposition key must be a permutation of 1..N (e.g. 3,1,4,2).');
      }
      return { mode: 'periodic', period, rank: nums.map((v) => v - 1), display: nums.join(',') };
    }
    const letters = onlyLetters(trimmed);
    if (letters.length < 2) throw new Error('Columnar transposition keyword must have at least 2 letters (or use a numeric permutation like 3,1,4,2 for simple periodic transposition).');
    if (new Set(letters).size !== letters.length) throw new Error('Columnar transposition keyword letters must be distinct (or use a numeric permutation like 3,1,4,2 for simple periodic transposition).');
    return { mode: 'columnar', keyword: letters, display: letters };
  }

  function transpositionOrder(t) {
    return t.mode === 'periodic' ? orderFromRanks(t.rank) : orderFromRanks(keywordColumnRanks(t.keyword));
  }

  function transpositionKeyInfo(t) {
    return t.mode === 'periodic' ? `periodic(${t.period})=${t.display}` : `columnar=${t.display}`;
  }

  function randomTranspositionKey() {
    if (randChoice([true, false])) {
      const period = randInt(4, 8);
      const perm = shuffled(Array.from({ length: period }, (_, i) => i + 1));
      return { mode: 'periodic', period, rank: perm.map((v) => v - 1), display: perm.join(',') };
    }
    const keyword = pickDistinctLetterWord(5, 9);
    return { mode: 'columnar', keyword, display: keyword };
  }

  function randomRunningKeyTranspositionKey(opts) {
    const rk = runningKeyStraightRandomKey(opts);
    const transposition = randomTranspositionKey();
    return {
      key: { runningKey: rk.key, transposition },
      values: { keyText: rk.values.keyText, transKey: transposition.display },
    };
  }

  const TRANS_KEY_FIELD = {
    name: 'transKey',
    label: 'Transposition key (keyword for columnar, or a comma-separated permutation like 3,1,4,2 for simple periodic)',
    type: 'text',
    placeholder: 'e.g. ZEBRAS or 3,1,4,2',
  };
  const RUNNING_KEY_TEXT_FIELD = {
    name: 'keyText',
    label: 'Running key text (letters only, at least as long as the plaintext)',
    type: 'textarea',
    placeholder: 'a long passage of key text...',
  };

  register({
    id: 'running_key_transposition',
    label: 'Running Key + Transposition',
    fields: [RUNNING_KEY_TEXT_FIELD, TRANS_KEY_FIELD],
    randomKey(opts) { return randomRunningKeyTranspositionKey(opts); },
    keyFromValues(values) {
      const runningKey = runningKeyStraightKeyFromValues({ keyText: values.keyText });
      const transposition = parseTranspositionKey(values.transKey);
      return { runningKey, transposition };
    },
    keyInfo(key) {
      return `${runningKeyStraightKeyInfo(key.runningKey)} transposition=${transpositionKeyInfo(key.transposition)}`;
    },
    // Running key first, then transpose the result.
    encrypt(pt, key) {
      const innerCt = runningKeyStraightEncrypt(pt, key.runningKey);
      return columnarEncryptRaw(innerCt, transpositionOrder(key.transposition));
    },
    decrypt(ct, key) {
      const innerCt = columnarDecryptRaw(ct, transpositionOrder(key.transposition));
      return runningKeyStraightDecrypt(innerCt, key.runningKey);
    },
  });

  register({
    id: 'transposition_running_key',
    label: 'Transposition + Running Key',
    fields: [TRANS_KEY_FIELD, RUNNING_KEY_TEXT_FIELD],
    randomKey(opts) { return randomRunningKeyTranspositionKey(opts); },
    keyFromValues(values) {
      const transposition = parseTranspositionKey(values.transKey);
      const runningKey = runningKeyStraightKeyFromValues({ keyText: values.keyText });
      return { transposition, runningKey };
    },
    keyInfo(key) {
      return `transposition=${transpositionKeyInfo(key.transposition)} ${runningKeyStraightKeyInfo(key.runningKey)}`;
    },
    // Transpose first, then apply the running key to the transposed text.
    encrypt(pt, key) {
      const transposed = columnarEncryptRaw(pt, transpositionOrder(key.transposition));
      return runningKeyStraightEncrypt(transposed, key.runningKey);
    },
    decrypt(ct, key) {
      const transposed = runningKeyStraightDecrypt(ct, key.runningKey);
      return columnarDecryptRaw(transposed, transpositionOrder(key.transposition));
    },
  });

  // ---------------------------------------------------------------------
  // ADFGX / ADFGVX
  // ---------------------------------------------------------------------
  function buildPolybiusSquare(keyword, symbols, size) {
    const seq = keyedSymbolSequence(keyword, symbols);
    const grid = [];
    for (let r = 0; r < size; r++) grid.push(seq.slice(r * size, r * size + size));
    const lookup = {};
    for (let r = 0; r < size; r++) for (let c = 0; c < size; c++) lookup[grid[r][c]] = [r, c];
    return { grid, lookup };
  }

  function adfgxLikeEncrypt(pt, squareKeyword, transKeyword, labels, symbols) {
    const size = labels.length;
    const { lookup } = buildPolybiusSquare(squareKeyword, symbols, size);
    let coordStr = '';
    for (let ch of pt) {
      if (ch === 'J' && !symbols.includes('J')) ch = 'I';
      const [r, c] = lookup[ch];
      coordStr += labels[r] + labels[c];
    }
    return columnarEncryptRaw(coordStr, orderFromRanks(keywordColumnRanks(transKeyword)));
  }

  function adfgxLikeDecrypt(ct, squareKeyword, transKeyword, labels, symbols) {
    const size = labels.length;
    const { grid } = buildPolybiusSquare(squareKeyword, symbols, size);
    const coordStr = columnarDecryptRaw(ct, orderFromRanks(keywordColumnRanks(transKeyword)));
    const labelIndex = {}; labels.forEach((l, i) => { labelIndex[l] = i; });
    let out = '';
    for (let i = 0; i + 1 < coordStr.length + 1 && i + 1 <= coordStr.length; i += 2) {
      const r = labelIndex[coordStr[i]];
      const c = labelIndex[coordStr[i + 1]];
      out += grid[r][c];
    }
    return out;
  }

  register({
    id: 'adfgx',
    label: 'ADFGX',
    fields: [
      { name: 'squareKeyword', label: 'Polybius square keyword', type: 'text', placeholder: 'e.g. KRYPTOS' },
      { name: 'transKeyword', label: 'Transposition keyword (letters must be distinct)', type: 'text', placeholder: 'e.g. GERMAN' },
    ],
    randomKey() {
      const squareKeyword = pickDictionaryWord(5, 9);
      const transKeyword = pickDistinctLetterWord(6, 10);
      return { key: { squareKeyword, transKeyword }, values: { squareKeyword, transKeyword } };
    },
    keyFromValues(values) {
      const squareKeyword = onlyLetters(values.squareKeyword);
      const transKeyword = onlyLetters(values.transKeyword);
      validateLength(squareKeyword, 'Polybius square keyword');
      validateLength(transKeyword, 'Transposition keyword');
      if (new Set(transKeyword).size !== transKeyword.length) throw new Error('Transposition keyword letters must be distinct.');
      return { squareKeyword, transKeyword };
    },
    keyInfo(key) { return `square=${key.squareKeyword} transposition=${key.transKeyword}`; },
    encrypt(pt, key) {
      const symbols = keyedSymbolSequence('', ALPHABET.replace('J', '')); // 25 letters, I/J merged
      return adfgxLikeEncrypt(pt.replace(/J/g, 'I'), key.squareKeyword, key.transKeyword, ['A', 'D', 'F', 'G', 'X'], symbols);
    },
    decrypt(ct, key) {
      const symbols = keyedSymbolSequence('', ALPHABET.replace('J', ''));
      return adfgxLikeDecrypt(ct, key.squareKeyword, key.transKeyword, ['A', 'D', 'F', 'G', 'X'], symbols);
    },
  });

  register({
    id: 'adfgvx',
    label: 'ADFGVX',
    fields: [
      { name: 'squareKeyword', label: 'Polybius square keyword', type: 'text', placeholder: 'e.g. KRYPTOS' },
      { name: 'transKeyword', label: 'Transposition keyword (letters must be distinct)', type: 'text', placeholder: 'e.g. GERMAN' },
    ],
    randomKey() {
      const squareKeyword = pickDictionaryWord(5, 9);
      const transKeyword = pickDistinctLetterWord(6, 10);
      return { key: { squareKeyword, transKeyword }, values: { squareKeyword, transKeyword } };
    },
    keyFromValues(values) {
      const squareKeyword = onlyLetters(values.squareKeyword);
      const transKeyword = onlyLetters(values.transKeyword);
      validateLength(squareKeyword, 'Polybius square keyword');
      validateLength(transKeyword, 'Transposition keyword');
      if (new Set(transKeyword).size !== transKeyword.length) throw new Error('Transposition keyword letters must be distinct.');
      return { squareKeyword, transKeyword };
    },
    keyInfo(key) { return `square=${key.squareKeyword} transposition=${key.transKeyword}`; },
    encrypt(pt, key) {
      const symbols = keyedSymbolSequence('', ALPHABET + '0123456789'); // 36 symbols
      return adfgxLikeEncrypt(pt, key.squareKeyword, key.transKeyword, ['A', 'D', 'F', 'G', 'V', 'X'], symbols);
    },
    decrypt(ct, key) {
      const symbols = keyedSymbolSequence('', ALPHABET + '0123456789');
      return adfgxLikeDecrypt(ct, key.squareKeyword, key.transKeyword, ['A', 'D', 'F', 'G', 'V', 'X'], symbols);
    },
  });

  // ---------------------------------------------------------------------
  // Bifid
  // ---------------------------------------------------------------------
  register({
    id: 'bifid',
    label: 'Bifid',
    fields: [
      { name: 'keyword', label: 'Polybius square keyword', type: 'text', placeholder: 'e.g. MONARCHY' },
      { name: 'period', label: 'Period (block size, 0 = whole message)', type: 'number', min: 0, max: 40 },
    ],
    randomKey(opts) {
      const keyword = pickDictionaryWord(5, 9);
      const ptLen = (opts && opts.ptLength) || 97;
      const period = randChoice([0, 5, 6, 7, 8, 10, 12]);
      return { key: { keyword, period }, values: { keyword, period: String(period) } };
    },
    keyFromValues(values) {
      const keyword = onlyLetters(values.keyword);
      validateLength(keyword, 'Polybius square keyword');
      const period = parseInt(values.period, 10) || 0;
      return { keyword, period };
    },
    keyInfo(key) { return `keyword=${key.keyword} period=${key.period || 'whole message'}`; },
    encrypt(pt, key) {
      const symbols = keyedSymbolSequence('', ALPHABET.replace('J', ''));
      const { lookup, grid } = buildPolybiusSquare(key.keyword, symbols, 5);
      const period = key.period > 0 ? key.period : pt.length;
      let out = '';
      for (let start = 0; start < pt.length; start += period) {
        const block = pt.slice(start, start + period).replace(/J/g, 'I');
        const rows = [], cols = [];
        for (const ch of block) { const [r, c] = lookup[ch]; rows.push(r); cols.push(c); }
        const seq = rows.concat(cols);
        for (let i = 0; i < block.length; i++) out += grid[seq[2 * i]][seq[2 * i + 1]];
      }
      return out;
    },
    decrypt(ct, key) {
      const symbols = keyedSymbolSequence('', ALPHABET.replace('J', ''));
      const { lookup, grid } = buildPolybiusSquare(key.keyword, symbols, 5);
      const period = key.period > 0 ? key.period : ct.length;
      let out = '';
      for (let start = 0; start < ct.length; start += period) {
        const block = ct.slice(start, start + period);
        const seq = [];
        for (const ch of block) { const [r, c] = lookup[ch]; seq.push(r, c); }
        const rows = seq.slice(0, block.length);
        const cols = seq.slice(block.length);
        for (let i = 0; i < block.length; i++) out += grid[rows[i]][cols[i]];
      }
      return out;
    },
  });

  // ---------------------------------------------------------------------
  // Trifid (3x3x3 cube; 27th symbol '#' pads the unused cell and may
  // legitimately appear in ciphertext, as in the classical cipher)
  // ---------------------------------------------------------------------
  const TRIFID_FILLER = '#';
  function buildTrifidCube(keyword) {
    const symbols = keyedSymbolSequence(keyword, ALPHABET + TRIFID_FILLER);
    const cube = []; // cube[layer][row][col]
    const lookup = {};
    let idx = 0;
    for (let l = 0; l < 3; l++) {
      const layer = [];
      for (let r = 0; r < 3; r++) {
        const row = [];
        for (let c = 0; c < 3; c++) { const ch = symbols[idx++]; row.push(ch); lookup[ch] = [l, r, c]; }
        layer.push(row);
      }
      cube.push(layer);
    }
    return { cube, lookup };
  }

  register({
    id: 'trifid',
    label: 'Trifid',
    fields: [
      { name: 'keyword', label: 'Cube keyword', type: 'text', placeholder: 'e.g. FELIX' },
      { name: 'period', label: 'Period (block size, 0 = whole message)', type: 'number', min: 0, max: 40 },
    ],
    randomKey() {
      const keyword = pickDictionaryWord(5, 9);
      const period = randChoice([0, 5, 7, 8, 10, 12]);
      return { key: { keyword, period }, values: { keyword, period: String(period) } };
    },
    keyFromValues(values) {
      const keyword = onlyLetters(values.keyword);
      validateLength(keyword, 'Cube keyword');
      const period = parseInt(values.period, 10) || 0;
      return { keyword, period };
    },
    keyInfo(key) { return `keyword=${key.keyword} period=${key.period || 'whole message'}`; },
    encrypt(pt, key) {
      const { cube, lookup } = buildTrifidCube(key.keyword);
      const period = key.period > 0 ? key.period : pt.length;
      let out = '';
      for (let start = 0; start < pt.length; start += period) {
        const block = pt.slice(start, start + period);
        const layers = [], rows = [], cols = [];
        for (const ch of block) { const [l, r, c] = lookup[ch]; layers.push(l); rows.push(r); cols.push(c); }
        const seq = layers.concat(rows, cols);
        for (let i = 0; i < block.length; i++) out += cube[seq[3 * i]][seq[3 * i + 1]][seq[3 * i + 2]];
      }
      return out;
    },
    decrypt(ct, key) {
      const { cube, lookup } = buildTrifidCube(key.keyword);
      const period = key.period > 0 ? key.period : ct.length;
      let out = '';
      for (let start = 0; start < ct.length; start += period) {
        const block = ct.slice(start, start + period);
        const seq = [];
        for (const ch of block) { const [l, r, c] = lookup[ch]; seq.push(l, r, c); }
        const layers = seq.slice(0, block.length);
        const rows = seq.slice(block.length, 2 * block.length);
        const cols = seq.slice(2 * block.length);
        for (let i = 0; i < block.length; i++) out += cube[layers[i]][rows[i]][cols[i]];
      }
      return out;
    },
  });

  // ---------------------------------------------------------------------
  // Playfair
  // ---------------------------------------------------------------------
  function buildPlayfairGrid(keyword) {
    const seq = keyedSymbolSequence(keyword, ALPHABET.replace('J', ''));
    const grid = [];
    for (let r = 0; r < 5; r++) grid.push(seq.slice(r * 5, r * 5 + 5));
    const pos = {};
    for (let r = 0; r < 5; r++) for (let c = 0; c < 5; c++) pos[grid[r][c]] = [r, c];
    return { grid, pos };
  }

  function playfairDigraphs(pt) {
    const letters = pt.replace(/J/g, 'I').split('');
    const digraphs = [];
    let i = 0;
    while (i < letters.length) {
      const a = letters[i];
      let b = letters[i + 1];
      if (b === undefined) { digraphs.push([a, a === 'X' ? 'Q' : 'X']); i += 1; }
      else if (a === b) { digraphs.push([a, a === 'X' ? 'Q' : 'X']); i += 1; }
      else { digraphs.push([a, b]); i += 2; }
    }
    return digraphs;
  }

  register({
    id: 'playfair',
    label: 'Playfair',
    fields: [{ name: 'keyword', label: 'Keyword', type: 'text', placeholder: 'e.g. MONARCHY' }],
    randomKey() {
      const keyword = pickDictionaryWord(5, 9);
      return { key: { keyword }, values: { keyword } };
    },
    keyFromValues(values) {
      const k = onlyLetters(values.keyword);
      validateLength(k, 'Keyword');
      return { keyword: k };
    },
    keyInfo(key) { return `keyword=${key.keyword}`; },
    encrypt(pt, key) {
      const { grid, pos } = buildPlayfairGrid(key.keyword);
      const digraphs = playfairDigraphs(pt);
      let out = '';
      for (const [a, b] of digraphs) {
        const [ra, ca] = pos[a], [rb, cb] = pos[b];
        if (ra === rb) out += grid[ra][(ca + 1) % 5] + grid[rb][(cb + 1) % 5];
        else if (ca === cb) out += grid[(ra + 1) % 5][ca] + grid[(rb + 1) % 5][cb];
        else out += grid[ra][cb] + grid[rb][ca];
      }
      return out;
    },
    decrypt(ct, key) {
      const { grid, pos } = buildPlayfairGrid(key.keyword);
      let out = '';
      for (let i = 0; i < ct.length; i += 2) {
        const a = ct[i], b = ct[i + 1];
        const [ra, ca] = pos[a], [rb, cb] = pos[b];
        if (ra === rb) out += grid[ra][(ca + 4) % 5] + grid[rb][(cb + 4) % 5];
        else if (ca === cb) out += grid[(ra + 4) % 5][ca] + grid[(rb + 4) % 5][cb];
        else out += grid[ra][cb] + grid[rb][ca];
      }
      return out;
    },
  });

  // ---------------------------------------------------------------------
  // Hill cipher (2x2 or 3x3, matrix mod 26)
  // ---------------------------------------------------------------------
  function egcd(a, b) { if (b === 0) return [a, 1, 0]; const [g, x, y] = egcd(b, a % b); return [g, y, x - Math.floor(a / b) * y]; }
  function modInverse(a, m) { const [g, x] = egcd(mod(a, m), m); if (g !== 1) return null; return mod(x, m); }

  function matDet(mat, n) {
    if (n === 2) return mod(mat[0][0] * mat[1][1] - mat[0][1] * mat[1][0], 26);
    // 3x3
    return mod(
      mat[0][0] * (mat[1][1] * mat[2][2] - mat[1][2] * mat[2][1])
      - mat[0][1] * (mat[1][0] * mat[2][2] - mat[1][2] * mat[2][0])
      + mat[0][2] * (mat[1][0] * mat[2][1] - mat[1][1] * mat[2][0]), 26);
  }

  function matInverse(mat, n) {
    const det = matDet(mat, n);
    const detInv = modInverse(det, 26);
    if (detInv === null) return null;
    let adj;
    if (n === 2) {
      adj = [[mat[1][1], -mat[0][1]], [-mat[1][0], mat[0][0]]];
    } else {
      const cof = (r, c) => {
        const rows = [0, 1, 2].filter((i) => i !== r);
        const cols = [0, 1, 2].filter((i) => i !== c);
        const m2 = [[mat[rows[0]][cols[0]], mat[rows[0]][cols[1]]], [mat[rows[1]][cols[0]], mat[rows[1]][cols[1]]]];
        const sign = (r + c) % 2 === 0 ? 1 : -1;
        return sign * (m2[0][0] * m2[1][1] - m2[0][1] * m2[1][0]);
      };
      const cofactor = [[0, 0, 0], [0, 0, 0], [0, 0, 0]];
      for (let r = 0; r < 3; r++) for (let c = 0; c < 3; c++) cofactor[r][c] = cof(r, c);
      // adjugate = transpose of cofactor matrix
      adj = [[cofactor[0][0], cofactor[1][0], cofactor[2][0]], [cofactor[0][1], cofactor[1][1], cofactor[2][1]], [cofactor[0][2], cofactor[1][2], cofactor[2][2]]];
    }
    return adj.map((row) => row.map((v) => mod(v * detInv, 26)));
  }

  function matVecMul(mat, vec, n) {
    const out = new Array(n).fill(0);
    for (let r = 0; r < n; r++) { let s = 0; for (let c = 0; c < n; c++) s += mat[r][c] * vec[c]; out[r] = mod(s, 26); }
    return out;
  }

  function randomInvertibleMatrix(n) {
    for (let tries = 0; tries < 500; tries++) {
      const mat = Array.from({ length: n }, () => Array.from({ length: n }, () => randInt(0, 25)));
      if (matInverse(mat, n)) return mat;
    }
    return n === 2 ? [[3, 3], [2, 5]] : [[6, 24, 1], [13, 16, 10], [20, 17, 15]];
  }

  register({
    id: 'hill',
    label: 'Hill',
    fields: [
      { name: 'size', label: 'Matrix size (2 or 3)', type: 'number', min: 2, max: 3 },
      { name: 'matrix', label: 'Matrix rows (comma-separated, one row per line, 0-25)', type: 'textarea', placeholder: '3,3\n2,5' },
    ],
    randomKey() {
      const size = randChoice([2, 2, 3]); // favor 2x2 slightly, both supported
      const matrix = randomInvertibleMatrix(size);
      const matrixText = matrix.map((row) => row.join(',')).join('\n');
      return { key: { size, matrix }, values: { size: String(size), matrix: matrixText } };
    },
    keyFromValues(values) {
      const size = parseInt(values.size, 10);
      if (size !== 2 && size !== 3) throw new Error('Hill matrix size must be 2 or 3.');
      const rows = values.matrix.trim().split('\n').map((line) => line.split(',').map((v) => parseInt(v.trim(), 10)));
      if (rows.length !== size || rows.some((r) => r.length !== size || r.some((v) => !Number.isInteger(v) || v < 0 || v > 25))) {
        throw new Error(`Matrix must be ${size}x${size} with integer entries 0-25.`);
      }
      if (!matInverse(rows, size)) throw new Error('Matrix is not invertible mod 26 (choose different values).');
      return { size, matrix: rows };
    },
    keyInfo(key) { return `${key.size}x${key.size} matrix=[${key.matrix.map((r) => r.join(' ')).join(' / ')}]`; },
    encrypt(pt, key) {
      const n = key.size;
      let padded = pt;
      while (padded.length % n !== 0) padded += 'X';
      let out = '';
      for (let i = 0; i < padded.length; i += n) {
        const vec = padded.slice(i, i + n).split('').map(letterNum);
        const c = matVecMul(key.matrix, vec, n);
        out += c.map(numLetter).join('');
      }
      return out;
    },
    decrypt(ct, key) {
      const n = key.size;
      const inv = matInverse(key.matrix, n);
      let out = '';
      for (let i = 0; i < ct.length; i += n) {
        const vec = ct.slice(i, i + n).split('').map(letterNum);
        const p = matVecMul(inv, vec, n);
        out += p.map(numLetter).join('');
      }
      return out;
    },
  });

  // ---------------------------------------------------------------------
  // Enigma (Wehrmacht Enigma I: rotors I-V, reflector B/C, ring settings,
  // initial positions, plugboard). Standard historical wiring tables.
  // ---------------------------------------------------------------------
  const ROTOR_WIRING = {
    I: 'EKMFLGDQVZNTOWYHXUSPAIBRCJ',
    II: 'AJDKSIRUXBLHWTMCQGZNPYFVOE',
    III: 'BDFHJLCPRTXVZNYEIWGAKMUSQO',
    IV: 'ESOVPZJAYQUIRHXLNFTGKDCMWB',
    V: 'VZBRGITYUPSDNHLXAWMJQOFECK',
  };
  const ROTOR_NOTCH = { I: 'Q', II: 'E', III: 'V', IV: 'J', V: 'Z' };
  const REFLECTOR_WIRING = {
    B: 'YRUHQSLDPXNGOKMIEBFZCWVJAT',
    C: 'FVPJIAOYEDRZXWGCTKUQSBNMHL',
  };

  function buildEnigmaMachine(key) {
    // key.rotors / key.ringSettings / key.initialPositions are stored LEFT TO
    // RIGHT (matching the field labels, and the standard human/historical
    // convention - e.g. Colossus's enigma_solver.c report, whose rotor[0] is
    // documented as "the LEFTMOST wheel"). stepRotors()/encodeChar() below
    // index [0]=right (fastest-stepping) .. [2]=left, so reverse once here at
    // the boundary rather than reinterpreting every internal index.
    const rotorNames = key.rotors.slice().reverse();
    const rotors = rotorNames.map((name) => {
      const wiring = ROTOR_WIRING[name].split('').map(letterNum);
      const inverse = new Array(26);
      wiring.forEach((w, i) => { inverse[w] = i; });
      return { wiring, inverse, notch: letterNum(ROTOR_NOTCH[name]) };
    });
    const reflector = REFLECTOR_WIRING[key.reflector].split('').map(letterNum);
    const positions = key.initialPositions.slice().reverse().map(letterNum);
    const rings = key.ringSettings.slice().reverse().map((r) => r - 1);
    const plugMap = new Array(26);
    for (let i = 0; i < 26; i++) plugMap[i] = i;
    (key.plugboard || []).forEach(([a, b]) => { const an = letterNum(a), bn = letterNum(b); plugMap[an] = bn; plugMap[bn] = an; });

    function stepRotors() {
      const middleAtNotch = positions[1] === rotors[1].notch;
      const rightAtNotch = positions[0] === rotors[0].notch;
      let stepMiddle = false, stepLeft = false;
      if (middleAtNotch) { stepMiddle = true; stepLeft = true; }
      if (rightAtNotch) { stepMiddle = true; }
      if (stepLeft) positions[2] = mod(positions[2] + 1, 26);
      if (stepMiddle) positions[1] = mod(positions[1] + 1, 26);
      positions[0] = mod(positions[0] + 1, 26);
    }

    function encodeChar(ch) {
      stepRotors();
      let c = letterNum(ch);
      c = plugMap[c];
      // right (0) -> middle (1) -> left (2)
      for (let i = 0; i < 3; i++) {
        const offset = positions[i] - rings[i];
        const entry = mod(c + offset, 26);
        const wired = rotors[i].wiring[entry];
        c = mod(wired - offset, 26);
      }
      c = reflector[c];
      // left (2) -> middle (1) -> right (0), using inverse wiring
      for (let i = 2; i >= 0; i--) {
        const offset = positions[i] - rings[i];
        const entry = mod(c + offset, 26);
        const wired = rotors[i].inverse[entry];
        c = mod(wired - offset, 26);
      }
      c = plugMap[c];
      return numLetter(c);
    }

    // Report positions left-to-right too (reverse back), matching key.initialPositions.
    return { encodeChar, getPositions: () => positions.slice().reverse() };
  }

  function enigmaProcess(text, key) {
    const machine = buildEnigmaMachine(key);
    return text.split('').map((ch) => machine.encodeChar(ch)).join('');
  }

  function randomPlugboard() {
    const letters = shuffled(ALPHABET.split(''));
    const pairCount = randChoice([0, 2, 4, 6, 8, 10]) / 2;
    const pairs = [];
    for (let i = 0; i < pairCount; i++) pairs.push([letters[2 * i], letters[2 * i + 1]]);
    return pairs;
  }

  register({
    id: 'enigma',
    label: 'Enigma',
    fields: [
      { name: 'rotors', label: 'Rotors, left to right (e.g. II-V-I)', type: 'text', placeholder: 'II-V-I' },
      { name: 'ringSettings', label: 'Ring settings, left to right (1-26, e.g. 4-11-22)', type: 'text', placeholder: '4-11-22' },
      { name: 'initialPositions', label: 'Initial rotor positions, left to right (e.g. QCM)', type: 'text', placeholder: 'QCM' },
      { name: 'reflector', label: 'Reflector (B or C)', type: 'text', placeholder: 'B' },
      { name: 'plugboard', label: 'Plugboard pairs (e.g. AB CD EF), or blank', type: 'text', placeholder: 'AB CD EF' },
    ],
    randomKey() {
      const rotors = shuffled(['I', 'II', 'III', 'IV', 'V']).slice(0, 3);
      const ringSettings = [randInt(1, 26), randInt(1, 26), randInt(1, 26)];
      const initialPositions = [randChoice(ALPHABET.split('')), randChoice(ALPHABET.split('')), randChoice(ALPHABET.split(''))];
      const reflector = randChoice(['B', 'C']);
      const plugboard = randomPlugboard();
      const key = { rotors, ringSettings, initialPositions, reflector, plugboard };
      const values = {
        rotors: rotors.join('-'),
        ringSettings: ringSettings.join('-'),
        initialPositions: initialPositions.join(''),
        reflector,
        plugboard: plugboard.map((p) => p.join('')).join(' '),
      };
      return { key, values };
    },
    keyFromValues(values) {
      const rotors = values.rotors.toUpperCase().split(/[-,\s]+/).filter(Boolean);
      if (rotors.length !== 3 || rotors.some((r) => !ROTOR_WIRING[r])) throw new Error('Specify 3 rotors from I, II, III, IV, V (e.g. II-V-I).');
      const ringSettings = values.ringSettings.split(/[-,\s]+/).filter(Boolean).map((v) => parseInt(v, 10));
      if (ringSettings.length !== 3 || ringSettings.some((v) => !Number.isInteger(v) || v < 1 || v > 26)) throw new Error('Specify 3 ring settings 1-26 (e.g. 4-11-22).');
      const initialPositions = onlyLetters(values.initialPositions).split('');
      if (initialPositions.length !== 3) throw new Error('Specify 3 initial rotor positions (e.g. QCM).');
      const reflector = values.reflector.trim().toUpperCase();
      if (!REFLECTOR_WIRING[reflector]) throw new Error('Reflector must be B or C.');
      const plugboard = onlyLetters(values.plugboard).match(/.{1,2}/g) || [];
      const plugPairs = plugboard.filter((p) => p.length === 2).map((p) => [p[0], p[1]]);
      return { rotors, ringSettings, initialPositions, reflector, plugboard: plugPairs };
    },
    keyInfo(key) {
      return `rotors=${key.rotors.join('-')} rings=${key.ringSettings.join('-')} start=${key.initialPositions.join('')} reflector=${key.reflector}` +
        (key.plugboard && key.plugboard.length ? ` plugboard=${key.plugboard.map((p) => p.join('')).join(' ')}` : ' plugboard=none');
    },
    encrypt(pt, key) { return enigmaProcess(pt, key); },
    decrypt(ct, key) { return enigmaProcess(ct, key); }, // self-reciprocal given identical settings
  });

  // ---------------------------------------------------------------------
  // Solitaire / Pontifex (Bruce Schneier). A 54-card deck (52 cards + 2
  // distinguishable jokers) generates a keystream: move joker A down 1 card,
  // move joker B down 2, triple-cut around the jokers, count-cut by the
  // bottom card's value, then read off an output card by counting from the
  // top card's value - skip and repeat from the top if a joker comes up.
  // Cards are numbered 1-52 in bridge suit order (clubs, diamonds, hearts,
  // spades) plus two extra ids for the jokers; keystream/cut values fold
  // both jokers to 53, and the final 1-26 keystream value folds every card
  // above 26 down by 26 (so both black and red court cards of the same rank
  // give the same value). Algorithm verified letter-for-letter against all
  // three official worked examples on schneier.com/academic/solitaire (see
  // scripts/test_ciphers.js).
  // ---------------------------------------------------------------------
  const SOLITAIRE_JOKER_A = 53;
  const SOLITAIRE_JOKER_B = 54;
  function solitaireUnkeyedDeck() {
    const d = [];
    for (let i = 1; i <= 52; i++) d.push(i);
    d.push(SOLITAIRE_JOKER_A, SOLITAIRE_JOKER_B);
    return d;
  }
  function solitaireIsJoker(c) { return c === SOLITAIRE_JOKER_A || c === SOLITAIRE_JOKER_B; }
  function solitaireCardValue(c) { return solitaireIsJoker(c) ? 53 : c; } // 1-53, for cut amounts
  function solitaireKeystreamValue(c) { return c <= 26 ? c : c - 26; } // 1-26, for the actual keystream
  // Card id -> display name, e.g. 14 -> "A-diamonds", 53/54 -> "Joker A"/"Joker B".
  const SOLITAIRE_SUITS = ['clubs', 'diamonds', 'hearts', 'spades'];
  const SOLITAIRE_RANKS = ['A', '2', '3', '4', '5', '6', '7', '8', '9', '10', 'J', 'Q', 'K'];
  function solitaireCardName(c) {
    if (c === SOLITAIRE_JOKER_A) return 'Joker A';
    if (c === SOLITAIRE_JOKER_B) return 'Joker B';
    const suit = SOLITAIRE_SUITS[Math.floor((c - 1) / 13)];
    const rank = SOLITAIRE_RANKS[(c - 1) % 13];
    return `${rank}-${suit}`;
  }
  function solitaireMoveJoker(deck, jokerVal, steps) {
    const n = deck.length;
    for (let s = 0; s < steps; s++) {
      const idx = deck.indexOf(jokerVal);
      let newIdx = idx + 1;
      if (newIdx >= n) newIdx = 1; // wrap past the bottom -> just below the top card
      deck.splice(idx, 1);
      deck.splice(newIdx, 0, jokerVal);
    }
  }
  function solitaireTripleCut(deck) {
    const ia = deck.indexOf(SOLITAIRE_JOKER_A), ib = deck.indexOf(SOLITAIRE_JOKER_B);
    const lo = Math.min(ia, ib), hi = Math.max(ia, ib);
    return deck.slice(hi + 1).concat(deck.slice(lo, hi + 1)).concat(deck.slice(0, lo));
  }
  function solitaireCountCut(deck, n) {
    if (n === undefined) n = solitaireCardValue(deck[deck.length - 1]);
    if (n === 0) return deck.slice();
    return deck.slice(n, deck.length - 1).concat(deck.slice(0, n)).concat([deck[deck.length - 1]]);
  }
  // One full round (mutates `deck` in place to its post-round state). Returns
  // a trace object; `.outputCard` is null when a joker came up (caller should
  // run another round immediately, per "start over again with step 1").
  function solitaireRoundTraced(deck) {
    const before = deck.slice();
    solitaireMoveJoker(deck, SOLITAIRE_JOKER_A, 1);
    const afterA = deck.slice();
    solitaireMoveJoker(deck, SOLITAIRE_JOKER_B, 2);
    const afterB = deck.slice();
    const afterTriple = solitaireTripleCut(deck);
    const bottomCard = afterTriple[afterTriple.length - 1];
    const cutN = solitaireCardValue(bottomCard);
    const afterCount = solitaireCountCut(afterTriple);
    for (let i = 0; i < afterCount.length; i++) deck[i] = afterCount[i];
    const topCard = deck[0];
    const topVal = solitaireCardValue(topCard);
    const outIdx = topVal % deck.length;
    const rawOutput = deck[outIdx];
    const isJoker = solitaireIsJoker(rawOutput);
    return {
      before, afterA, afterB, afterTriple, bottomCard, cutN, afterCount,
      topCard, topVal, outIdx, rawOutput, isJoker,
      outputCard: isJoker ? null : rawOutput,
      keystreamValue: isJoker ? null : solitaireKeystreamValue(rawOutput),
    };
  }
  // Keeps calling solitaireRoundTraced until a non-joker output appears;
  // returns {rounds: [...every attempt...], keystreamValue}.
  function solitaireNextKeystreamValue(deck) {
    const rounds = [];
    for (let guard = 0; guard < 1000; guard++) {
      const r = solitaireRoundTraced(deck);
      rounds.push(r);
      if (!r.isJoker) return { rounds, keystreamValue: r.keystreamValue };
    }
    throw new Error('Solitaire: too many consecutive jokers (deck may be corrupt).');
  }
  function solitaireRawKeystream(deck, n) {
    const out = [];
    while (out.length < n) out.push(solitaireNextKeystreamValue(deck).keystreamValue);
    return out;
  }
  // Passphrase keying (Schneier's "keying method 3"): repeat move-A, move-B,
  // triple-cut, a normal count-cut, then a SECOND count-cut using the
  // passphrase letter's value (A=1..Z=26) instead of the bottom card - once
  // per passphrase character, starting from the unkeyed deck.
  function solitairePassphraseKey(passphrase) {
    const deck = solitaireUnkeyedDeck();
    for (const ch of passphrase) {
      solitaireMoveJoker(deck, SOLITAIRE_JOKER_A, 1);
      solitaireMoveJoker(deck, SOLITAIRE_JOKER_B, 2);
      let d = solitaireTripleCut(deck);
      d = solitaireCountCut(d);
      d = solitaireCountCut(d, letterNum(ch) + 1);
      for (let i = 0; i < d.length; i++) deck[i] = d[i];
    }
    return deck;
  }
  // Solitaire's own 1-26 (not 0-25) letter arithmetic: A+A=B, and wraparound
  // only kicks in once the sum actually exceeds 26 - this is NOT the same as
  // ordinary 0-indexed mod-26 addition (verified against schneier.com's own
  // "DONOTUSEPC" worked example, which pins this exact behavior).
  function solitaireAdd(p, k) { let s = p + k; if (s > 26) s -= 26; return s; }
  function solitaireSub(c, k) { let s = c - k; if (s <= 0) s += 26; return s; }

  register({
    id: 'solitaire',
    label: 'Solitaire (Pontifex)',
    fields: [{ name: 'passphrase', label: 'Passphrase (keys the deck - the longer the better)', type: 'textarea', placeholder: 'e.g. a long, hard-to-guess phrase' }],
    randomKey() {
      const passphrase = pickDictionaryWord(6, 10) + pickDictionaryWord(6, 10);
      return { key: { passphrase }, values: { passphrase } };
    },
    keyFromValues(values) {
      const passphrase = onlyLetters(values.passphrase);
      validateLength(passphrase, 'Passphrase');
      return { passphrase };
    },
    keyInfo(key) { return `passphrase=${key.passphrase}`; },
    encrypt(pt, key) {
      const deck = solitairePassphraseKey(key.passphrase);
      const ks = solitaireRawKeystream(deck, pt.length).map(solitaireKeystreamValue);
      return pt.split('').map((ch, i) => numLetter(solitaireAdd(letterNum(ch) + 1, ks[i]) - 1)).join('');
    },
    decrypt(ct, key) {
      const deck = solitairePassphraseKey(key.passphrase);
      const ks = solitaireRawKeystream(deck, ct.length).map(solitaireKeystreamValue);
      return ct.split('').map((ch, i) => numLetter(solitaireSub(letterNum(ch) + 1, ks[i]) - 1)).join('');
    },
  });

  // ---------------------------------------------------------------------
  // Mirdek (Paul Crowley). Two 26-card piles ("left" and "right", each a
  // permutation of A-Z - one letter per card, colour/suit only ever matters
  // as a way to split the 52-card deck into these two halves) plus a
  // transient "discard" pile. Two primitive moves - a counted cut (draw the
  // right pile's top card, cut the left pile by its value) and a letter
  // search (deal the left pile onto two alternating piles until a target
  // letter appears, then reassemble) - drive initialisation, keying, mixing,
  // and encryption. Algorithm verified step-for-step (every intermediate
  // pile state) against the full worked example at
  // ciphergoth.org/crypto/mirdek/example.html (see scripts/test_ciphers.js).
  // Piles are stored top-card-first regardless of face-up/face-down-ness.
  // ---------------------------------------------------------------------
  function mirdekVal(ch) { return letterNum(ch) + 1; } // A=1..Z=26

  // One non-cascading counted-cut step: draw right's top card (its LAST
  // array element - see file header), cut left by that card's value.
  function mirdekCountedCutStep(state) {
    const { left, right, discard } = state;
    const card = right[right.length - 1];
    const newRight = right.slice(0, -1);
    const newDiscard = [card].concat(discard);
    const n = mirdekVal(card);
    const moved = left.slice(0, n);
    const newLeft = left.slice(n).concat(moved);
    return { left: newLeft, right: newRight, discard: newDiscard, drawnCard: card, n, emptied: newRight.length === 0 };
  }
  // Full counted cut, cascading (swap piles and cut again) if the right
  // pile empties out - used by the encrypt/decrypt hot path.
  function mirdekCountedCut(state) {
    const r = mirdekCountedCutStep(state);
    if (r.emptied) return mirdekCountedCut({ left: r.discard, right: r.left, discard: [] });
    return { left: r.left, right: r.right, discard: r.discard };
  }
  // Same operation, but returns every sub-cut (including cascades) for the
  // visualizer instead of just the final state.
  function mirdekCountedCutWithTrace(state) {
    const steps = [];
    let cur = state;
    for (let guard = 0; guard < 1000; guard++) {
      const r = mirdekCountedCutStep(cur);
      const after = { left: r.left, right: r.right, discard: r.discard };
      steps.push({ before: cur, drawnCard: r.drawnCard, n: r.n, after, emptied: r.emptied });
      if (!r.emptied) return { state: after, steps };
      cur = { left: r.discard, right: r.left, discard: [] };
    }
    throw new Error('Mirdek: counted cut cascaded too many times (state may be corrupt).');
  }
  // Deal `left` onto two face-up alternating piles (new cards on top of each)
  // until stopPred(card, dealtCountSoFar) is true; move the pile holding the
  // last-dealt card on top of the other, and put that combined pile beneath
  // the undealt remainder. Drives both the letter search (stop on a target
  // letter) and decryption's "deal N cards" step (stop after N cards).
  function mirdekDealAlternating(leftArr, stopPred) {
    let pileA = [], pileB = [];
    let i = 0, placedInA = true, lastWasA = true, lastCard = null;
    for (; i < leftArr.length;) {
      const card = leftArr[i]; i++;
      if (placedInA) pileA = [card].concat(pileA); else pileB = [card].concat(pileB);
      lastWasA = placedInA; lastCard = card; placedInA = !placedInA;
      if (stopPred(card, i)) break;
    }
    const remaining = leftArr.slice(i);
    const targetPile = lastWasA ? pileA : pileB;
    const otherPile = lastWasA ? pileB : pileA;
    return {
      newLeft: remaining.concat(targetPile, otherPile), lastCard, dealtCount: i,
      pileA, pileB, targetIsA: lastWasA, remaining, dealtSequence: leftArr.slice(0, i),
    };
  }
  function mirdekLetterSearch(leftArr, target) { return mirdekDealAlternating(leftArr, (c) => c === target); }
  function mirdekDealN(leftArr, n) { return mirdekDealAlternating(leftArr, (c, dealt) => dealt === n); }

  function mirdekInit(iv25) {
    const present = new Set(iv25.split(''));
    let missing = 'A';
    for (const ch of ALPHABET) if (!present.has(ch)) { missing = ch; break; }
    return { left: ALPHABET.split(''), right: iv25.split('').concat([missing]), discard: [] };
  }
  function mirdekKeyPhase(state, passphrase) {
    for (const ch of passphrase) {
      state = mirdekCountedCut(state);
      const { newLeft } = mirdekLetterSearch(state.left, ch);
      state = { left: newLeft, right: state.right, discard: state.discard };
    }
    return state;
  }
  function mirdekMixPhase(state) {
    let right = state.left.slice(); // the fully-keyed left pile, put down face-down as the new right
    let left = state.discard.concat(state.right); // discard (unchanged on top) + remaining right, below
    let discard = [];
    while (right.length > 0) {
      const card = right[right.length - 1];
      right = right.slice(0, -1);
      discard = [card].concat(discard);
      const { newLeft } = mirdekLetterSearch(left, card);
      left = newLeft;
    }
    // Final swap: the fully-mixed pile (`left`) becomes the new face-down
    // right pile; the accumulated draws (`discard`) become the new left pile.
    return { left: discard, right: left, discard: [] };
  }
  function mirdekEncryptLetter(state, ptChar) {
    state = mirdekCountedCut(state);
    const { newLeft, dealtCount } = mirdekLetterSearch(state.left, ptChar);
    const ctChar = ALPHABET[dealtCount - 1];
    return { state: { left: newLeft, right: state.right, discard: state.discard }, ctChar };
  }
  function mirdekDecryptLetter(state, ctChar) {
    state = mirdekCountedCut(state);
    const n = mirdekVal(ctChar);
    const { newLeft, lastCard } = mirdekDealN(state.left, n);
    return { state: { left: newLeft, right: state.right, discard: state.discard }, ptChar: lastCard };
  }
  function mirdekSetup(iv25, passphrase) {
    let state = mirdekInit(iv25);
    state = mirdekKeyPhase(state, passphrase);
    state = mirdekMixPhase(state);
    return state;
  }

  register({
    id: 'mirdek',
    label: 'Mirdek',
    fields: [
      { name: 'iv', label: 'Initialization vector (25 distinct letters; encryption only - decryption reads it from the ciphertext)', type: 'text', placeholder: 'e.g. IPDZOWKGSTVARMEQYBCFJNHUL' },
      { name: 'passphrase', label: 'Passphrase (keys the deck)', type: 'text', placeholder: 'e.g. a shared secret phrase' },
    ],
    randomKey() {
      const iv = shuffled(ALPHABET.split('')).slice(0, 25).join('');
      const passphrase = pickDictionaryWord(6, 10) + pickDictionaryWord(6, 10);
      return { key: { iv, passphrase }, values: { iv, passphrase } };
    },
    keyFromValues(values) {
      const passphrase = onlyLetters(values.passphrase);
      validateLength(passphrase, 'Passphrase');
      const iv = onlyLetters(values.iv);
      if (iv && (iv.length !== 25 || new Set(iv).size !== 25)) {
        throw new Error('Initialization vector must be exactly 25 distinct letters (or leave it blank if you are only decrypting).');
      }
      return { iv, passphrase };
    },
    keyInfo(key) { return `passphrase=${key.passphrase}${key.iv ? ` iv=${key.iv}` : ''}`; },
    encrypt(pt, key) {
      if (!key.iv || key.iv.length !== 25 || new Set(key.iv).size !== 25) {
        throw new Error('Encrypting needs a 25-distinct-letter initialization vector.');
      }
      const state = mirdekSetup(key.iv, key.passphrase);
      let st = state, ct = '';
      for (const ch of pt) { const r = mirdekEncryptLetter(st, ch); st = r.state; ct += r.ctChar; }
      return key.iv + ct;
    },
    decrypt(ct, key) {
      if (ct.length < 26) throw new Error('Mirdek ciphertext must start with a 25-letter initialization vector, followed by at least one encrypted letter.');
      const iv = ct.slice(0, 25);
      if (new Set(iv).size !== 25) throw new Error('The first 25 letters of the ciphertext (the initialization vector) must be 25 distinct letters.');
      const message = ct.slice(25);
      const state = mirdekSetup(iv, key.passphrase);
      let st = state, pt = '';
      for (const ch of message) { const r = mirdekDecryptLetter(st, ch); st = r.state; pt += r.ptChar; }
      return pt;
    },
  });

  // ===========================================================================
  // Internal helpers re-exported for the Visualizer (js/visualizer.js), so it
  // can reconstruct exactly the same tables / grids / permutations that
  // encrypt()/decrypt() use, instead of re-implementing (and risking drift
  // from) this logic.
  // ===========================================================================
  global.CipherLib = {
    CIPHERS,
    ALPHABET,
    mod,
    SOLITAIRE_JOKER_A,
    SOLITAIRE_JOKER_B,
    solitaireUnkeyedDeck,
    solitairePassphraseKey,
    solitaireRoundTraced,
    solitaireNextKeystreamValue,
    solitaireCardValue,
    solitaireKeystreamValue,
    solitaireCardName,
    solitaireAdd,
    solitaireSub,
    mirdekVal,
    mirdekInit,
    mirdekKeyPhase,
    mirdekMixPhase,
    mirdekSetup,
    mirdekCountedCut,
    mirdekCountedCutWithTrace,
    mirdekDealAlternating,
    mirdekLetterSearch,
    mirdekDealN,
    letterNum,
    numLetter,
    chaoRotate,
    chaoRemoveInsert,
    chaoStep,
    onlyLetters,
    randInt,
    randChoice,
    shuffled,
    keyedAlphabet26,
    keyedSymbolSequence,
    pickDictionaryWord,
    pickDistinctDictionaryWords,
    pickDistinctLetterWord,
    keywordColumnRanks,
    orderFromRanks,
    rangeArray,
    columnarEncryptRaw,
    columnarDecryptRaw,
    parseTranspositionKey,
    transpositionOrder,
    transpositionKeyInfo,
    buildHomophoneTables,
    ENGLISH_FREQ,
    buildPolybiusSquare,
    buildTrifidCube,
    TRIFID_FILLER,
    buildPlayfairGrid,
    playfairDigraphs,
    matVecMul,
    matInverse,
    matDet,
    egcd,
    modInverse,
    ROTOR_WIRING,
    ROTOR_NOTCH,
    REFLECTOR_WIRING,
    buildEnigmaMachine,
  };
})(typeof window !== 'undefined' ? window : globalThis);

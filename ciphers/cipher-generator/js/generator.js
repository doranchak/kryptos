// ============================================================================
// Plaintext-sampling + bulk cipher-generation engine.
//
// Selects a random contiguous run of whole words from a random corpus file
// whose combined letter count (no spaces) exactly matches a target length,
// rejects runs that don't look like normal English (repetition/low entropy),
// then encrypts the run with a freshly randomized key for the chosen cipher.
// ============================================================================

(function (global) {
  'use strict';

  const { randInt } = global.CipherLib;

  // ---------------------------------------------------------------------
  // Corpus word-array cache (split each corpus text once, lazily).
  // ---------------------------------------------------------------------
  const wordsCache = new WeakMap();
  function corpusWords(entry) {
    let w = wordsCache.get(entry);
    if (!w) { w = entry.text.split(' ').filter(Boolean); wordsCache.set(entry, w); }
    return w;
  }

  // ---------------------------------------------------------------------
  // "Looks like normal English" heuristic: reject sequences with a very
  // skewed letter distribution (low Shannon entropy) or long runs of a
  // repeated letter - the kind of degenerate text that occasionally results
  // from picking up stray boilerplate/list fragments from a corpus.
  // ---------------------------------------------------------------------
  function passesEntropyFilter(seqNoSpaces) {
    const n = seqNoSpaces.length;
    if (n === 0) return false;
    const counts = {};
    let maxRun = 1, curRun = 1;
    for (let i = 0; i < n; i++) {
      const ch = seqNoSpaces[i];
      counts[ch] = (counts[ch] || 0) + 1;
      if (i > 0) {
        if (ch === seqNoSpaces[i - 1]) { curRun++; maxRun = Math.max(maxRun, curRun); }
        else curRun = 1;
      }
    }
    if (maxRun >= 5) return false; // e.g. "AAAAA" - never happens in normal English
    let entropy = 0;
    for (const ch in counts) {
      const p = counts[ch] / n;
      entropy -= p * Math.log2(p);
    }
    // English unigram entropy is ~4.15 bits; reject sequences that are far
    // flatter/more repetitive than that. Short sequences get a slightly
    // lower bar since sample-to-sample variance is higher.
    const threshold = n < 40 ? 3.2 : 3.55;
    if (entropy < threshold) return false;
    // no single letter should dominate the sequence
    const maxCount = Math.max(...Object.values(counts));
    if (maxCount / n > 0.28) return false;
    return true;
  }

  // Up to `maxLen` characters of the text immediately preceding word index
  // `start` in the same corpus (no spaces, not necessarily word-aligned -
  // key text doesn't need whole words, only the plaintext selection does).
  // Used by ciphers whose key is meant to be a contiguous continuation of
  // the same source passage (e.g. "Running Key ACA") rather than unrelated
  // text; returns a shorter (possibly empty) string if the selection starts
  // too close to the beginning of its corpus file.
  function precedingTextFor(words, start, maxLen) {
    let acc = '';
    for (let j = start - 1; j >= 0 && acc.length < maxLen; j--) acc = words[j] + acc;
    return acc.length > maxLen ? acc.slice(acc.length - maxLen) : acc;
  }

  // ---------------------------------------------------------------------
  // Pick a random contiguous run of whole words (from a random corpus file,
  // starting at a random word position) whose combined length exactly
  // matches targetLength letters (no spaces), no word truncated.
  // ---------------------------------------------------------------------
  function pickPlaintextSequence(targetLength, maxAttempts) {
    const corpora = global.CIPHERGEN_CORPORA || [];
    if (corpora.length === 0) throw new Error('No corpora loaded.');
    maxAttempts = maxAttempts || 4000;
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      const src = corpora[randInt(0, corpora.length - 1)];
      const words = corpusWords(src);
      if (words.length === 0) continue;
      const start = randInt(0, words.length - 1);
      let sum = 0;
      const chosen = [];
      for (let j = start; j < words.length; j++) {
        const w = words[j];
        sum += w.length;
        if (sum > targetLength) break;
        chosen.push(w);
        if (sum === targetLength) {
          const noSpaces = chosen.join('');
          if (passesEntropyFilter(noSpaces)) {
            const precedingText = precedingTextFor(words, start, targetLength);
            return { words: chosen, corpusFile: src.file, startIndex: start, precedingText };
          }
          break;
        }
      }
    }
    return null;
  }

  // ---------------------------------------------------------------------
  // Per-cipher expansion model: how ciphertext length relates to plaintext
  // length, used only to seed a good first guess for the plaintext length
  // that will hit a *ciphertext* length target (see pickForCiphertextLength
  // below, which then verifies/corrects against the real encrypt() output -
  // so this table only needs to be approximately right, not exact; ciphers
  // with content-dependent padding, like Playfair and Hill, are fine left
  // at the 1:1 default and get corrected by the search itself).
  // ---------------------------------------------------------------------
  const LENGTH_MODEL = {
    homophonic_substitution: { ratio: 2, offset: 0 }, // always exactly 2 digits per letter
    adfgx: { ratio: 2, offset: 0 },                    // always exactly 2 coordinate letters per letter
    adfgvx: { ratio: 2, offset: 0 },
    mirdek: { ratio: 1, offset: 25 },                  // 25-letter IV always prepended to the ciphertext
  };
  const DEFAULT_LENGTH_MODEL = { ratio: 1, offset: 0 };

  function estimatePlaintextLength(cipherId, targetCiphertextLength) {
    const { ratio, offset } = LENGTH_MODEL[cipherId] || DEFAULT_LENGTH_MODEL;
    return Math.max(1, Math.round((targetCiphertextLength - offset) / ratio));
  }

  // ---------------------------------------------------------------------
  // Pick a (plaintext, key, ciphertext) triple whose ciphertext length is
  // exactly `targetCiphertextLength` when achievable, and never longer.
  // Starting from the LENGTH_MODEL estimate above, repeatedly pick a
  // whole-word plaintext of the current guessed length, encrypt it for
  // real, and correct the guess from the measured ciphertext length -
  // exact-ratio ciphers (most of them) converge on the first try;
  // content-dependent ones (Playfair's double-letter fillers, Hill's
  // block-size padding) take a few more. The longest ciphertext seen that
  // does not exceed the target is kept as a fallback in case the target
  // can never be hit exactly (e.g. an odd target for a ratio-2 cipher like
  // Homophonic/ADFGX/ADFGVX, or a target shorter than Mirdek's fixed
  // 25-letter IV overhead).
  // ---------------------------------------------------------------------
  function pickForCiphertextLength(def, cipherId, targetCiphertextLength, maxAttempts) {
    maxAttempts = maxAttempts || 20;
    let guessLen = estimatePlaintextLength(cipherId, targetCiphertextLength);
    const triedLengths = new Set();
    let best = null;
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      if (guessLen < 1) break;
      while (guessLen > 1 && triedLengths.has(guessLen)) guessLen--;
      if (triedLengths.has(guessLen)) break;
      triedLengths.add(guessLen);

      const seq = pickPlaintextSequence(guessLen);
      if (!seq) { guessLen--; continue; }
      const ptNoSpaces = seq.words.join('');
      let key, values, ciphertext;
      try {
        const rk = def.randomKey({ ptLength: ptNoSpaces.length, precedingText: seq.precedingText });
        key = rk.key; values = rk.values;
        ciphertext = def.encrypt(ptNoSpaces, key);
      } catch (e) {
        guessLen--;
        continue;
      }

      const candidate = { seq, ptNoSpaces, key, values, ciphertext };
      if (ciphertext.length === targetCiphertextLength) return candidate;
      if (ciphertext.length < targetCiphertextLength) {
        if (!best || ciphertext.length > best.ciphertext.length) best = candidate;
        guessLen += Math.max(1, targetCiphertextLength - ciphertext.length);
      } else {
        guessLen -= Math.max(1, ciphertext.length - targetCiphertextLength);
      }
    }
    return best;
  }

  // ---------------------------------------------------------------------
  // Bulk generation. Runs in synchronous chunks with a callback between
  // chunks (via setTimeout) so the browser tab stays responsive and a
  // progress bar / cancel button can be honored for large quantities.
  // ---------------------------------------------------------------------
  function generateCiphersAsync(opts) {
    const { cipherId, targetLength, quantity, onProgress, onDone, onError, isCancelled } = opts;
    const def = global.CipherLib.CIPHERS[cipherId];
    if (!def) { onError(new Error(`Unknown cipher: ${cipherId}`)); return; }

    const results = [];
    let skipped = 0;
    let i = 0;
    const CHUNK = 40;

    function step() {
      if (isCancelled && isCancelled()) { onDone(results, skipped, true); return; }
      const end = Math.min(quantity, i + CHUNK);
      for (; i < end; i++) {
        const found = pickForCiphertextLength(def, cipherId, targetLength);
        if (!found) { skipped++; continue; }
        const { seq, ptNoSpaces, key, ciphertext } = found;
        results.push({
          index: results.length + 1,
          cipherLabel: def.label,
          keyInfo: def.keyInfo(key),
          ciphertext,
          plaintextNoSpaces: ptNoSpaces,
          plaintextWithSpaces: seq.words.join(' '),
          corpusFile: seq.corpusFile,
        });
      }
      onProgress(i, quantity, results.length);
      if (i < quantity) {
        setTimeout(step, 0);
      } else {
        onDone(results, skipped, false);
      }
    }
    step();
  }

  function resultsToCsv(results) {
    const header = ['cipher type label', 'key information', 'ciphertext', 'plaintext without spaces', 'plaintext with spaces'];
    const rows = [header];
    for (const r of results) {
      rows.push([r.cipherLabel, r.keyInfo, r.ciphertext, r.plaintextNoSpaces, r.plaintextWithSpaces]);
    }
    return rows.map((row) => row.map(csvEscape).join(',')).join('\r\n');
  }

  function csvEscape(value) {
    const s = String(value == null ? '' : value);
    if (/[",\r\n]/.test(s)) return '"' + s.replace(/"/g, '""') + '"';
    return s;
  }

  global.CipherGenerator = {
    pickPlaintextSequence,
    passesEntropyFilter,
    estimatePlaintextLength,
    pickForCiphertextLength,
    generateCiphersAsync,
    resultsToCsv,
  };
})(typeof window !== 'undefined' ? window : globalThis);

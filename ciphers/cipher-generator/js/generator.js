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

  // Accepts either a plain number (an exact target - min and max both equal
  // to it) or a `{min, max}` object (a length range, inclusive on both
  // ends), and always returns the latter shape, so the search below only
  // has to know about ranges. An exact target is just the degenerate
  // range [target, target].
  function normalizeLengthSpec(lengthSpec) {
    if (typeof lengthSpec === 'number') return { min: lengthSpec, max: lengthSpec };
    return { min: lengthSpec.min, max: lengthSpec.max };
  }

  // ---------------------------------------------------------------------
  // Pick a (plaintext, key, ciphertext) triple whose ciphertext length
  // falls within `lengthSpec` (an exact target, or a `{min, max}` range,
  // inclusive) when achievable, and never exceeds the range's max.
  // Starting from the LENGTH_MODEL estimate for a *random* point in the
  // range (a fresh pick on every call, so repeated calls - e.g. generating
  // a batch - land on varied lengths spread across the range instead of
  // all clustering around one fixed point such as its middle), repeatedly
  // pick a whole-word plaintext of the current guessed length, encrypt it
  // for real, and correct the guess from the measured ciphertext length -
  // exact-ratio ciphers (most of them) converge on the first try, right on
  // that random point; content-dependent ones (Playfair's double-letter
  // fillers, Hill's block-size padding) take a few more and may land
  // elsewhere in the range. The longest in-range-or-under ciphertext seen
  // is kept as a fallback in case the range can never be hit at all (e.g.
  // an odd target for a ratio-2 cipher like Homophonic/ADFGX/ADFGVX, or a
  // range entirely below Mirdek's fixed 25-letter IV overhead).
  // ---------------------------------------------------------------------
  function pickForCiphertextLength(def, cipherId, lengthSpec, maxAttempts) {
    maxAttempts = maxAttempts || 20;
    const { min, max } = normalizeLengthSpec(lengthSpec);
    let guessLen = estimatePlaintextLength(cipherId, randInt(min, max));
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
      const len = ciphertext.length;
      if (len >= min && len <= max) return candidate;
      if (len <= max) {
        // Under the range (or under the exact target) - keep as a
        // fallback, and push the guess up toward the range.
        if (!best || len > best.ciphertext.length) best = candidate;
        guessLen += Math.max(1, min - len);
      } else {
        // Over the range (or over the exact target) - pull the guess back down.
        guessLen -= Math.max(1, len - max);
      }
    }
    return best;
  }

  // ---------------------------------------------------------------------
  // Batch generation for a single cipher type. Runs in synchronous chunks
  // with a callback between chunks (via setTimeout) so the browser tab
  // stays responsive and a progress bar / cancel button can be honored for
  // large quantities. `lengthSpec` is either an exact ciphertext-length
  // number or a `{min, max}` range (see pickForCiphertextLength above).
  // ---------------------------------------------------------------------
  function generateCiphersAsync(opts) {
    const { cipherId, lengthSpec, quantity, onProgress, onDone, onError, isCancelled } = opts;
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
        const found = pickForCiphertextLength(def, cipherId, lengthSpec);
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

  // ---------------------------------------------------------------------
  // Bulk generation: the same batch generation above, run in turn for
  // every cipher type in `cipherIds`, each targeting the same
  // `lengthSpec`/`quantity`. Cipher types are generated strictly one at a
  // time (not in parallel) so that:
  //   - progress/cancellation stay meaningful (one "step" for the caller's
  //     UI is "one cipher type finished", on top of that type's own
  //     internal chunked progress via onCipherProgress), and
  //   - the caller can act on each cipher type's results as soon as
  //     they're ready (e.g. trigger that type's CSV download) without
  //     waiting for every other type to finish first.
  // `onAllDone` receives every type's `{ cipherId, results, skipped }` so
  // the caller can also build one combined CSV across all types.
  // ---------------------------------------------------------------------
  function generateBulkAsync(opts) {
    const { cipherIds, lengthSpec, quantity, isCancelled, onCipherStart, onCipherProgress, onCipherDone, onAllDone, onError } = opts;
    const byType = [];
    let i = 0;

    function next() {
      if (isCancelled && isCancelled()) { onAllDone(byType, true); return; }
      if (i >= cipherIds.length) { onAllDone(byType, false); return; }
      const cipherId = cipherIds[i];
      if (!global.CipherLib.CIPHERS[cipherId]) { i++; next(); return; }
      const index = i;
      if (onCipherStart) onCipherStart(cipherId, index, cipherIds.length);
      generateCiphersAsync({
        cipherId,
        lengthSpec,
        quantity,
        isCancelled,
        onProgress: (done, total, produced) => { if (onCipherProgress) onCipherProgress(cipherId, done, total, produced, index, cipherIds.length); },
        onDone: (results, skipped, wasCancelled) => {
          byType.push({ cipherId, results, skipped });
          if (onCipherDone) onCipherDone(cipherId, results, skipped, wasCancelled, index, cipherIds.length);
          i++;
          if (wasCancelled) { onAllDone(byType, true); return; }
          setTimeout(next, 0);
        },
        onError: (e) => {
          if (onError) onError(e, cipherId);
          i++;
          setTimeout(next, 0);
        },
      });
    }
    next();
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
    generateBulkAsync,
    resultsToCsv,
  };
})(typeof window !== 'undefined' ? window : globalThis);

// ============================================================================
// UI wiring: cipher selection, manual encrypt/decrypt, and bulk generation
// with a paginated results table + CSV export.
// ============================================================================

(function () {
  'use strict';

  const { CIPHERS, onlyLetters } = window.CipherLib;

  // Dropdown order: every registered cipher id, sorted alphabetically by its
  // display label (so newly-registered ciphers show up automatically,
  // without needing to be added to a hand-maintained list here).
  const CIPHER_ORDER = Object.keys(CIPHERS).sort((a, b) => CIPHERS[a].label.localeCompare(CIPHERS[b].label));

  const CIPHER_HINTS = {
    simple_substitution: 'Each plaintext letter always maps to the same cipher letter; the cipher alphabet is a fixed permutation of A-Z.',
    homophonic_substitution: 'Each plaintext letter maps to one of several 2-digit codes (00-99), allocated proportional to English letter frequency so the ciphertext distribution is closer to flat. Ciphertext is digits, decoded 2 at a time.',
    chaocipher: 'Two 26-letter "disks" (left = ciphertext alphabet, right = plaintext alphabet) that dynamically reshuffle after every single letter, so the effective substitution never repeats and never settles into a fixed pattern.',
    chaocipher_single_wheel: 'One shared 26-letter wheel instead of Chaocipher\'s two: the ciphertext letter is read off the point diametrically opposite the plaintext letter (13 positions away - its own inverse, since 13+13=26), then the wheel gets the same single splice (rotate to the ciphertext letter, pull out its neighbor, reinsert opposite) as one of Chaocipher\'s disks.',
    chaocipher_symmetric: 'Chaocipher\'s exact two-disk lookup, but without Byrne\'s one asymmetry: both disks are permuted by the identical rule (rotate the just-used letter to the front, splice) instead of giving the plaintext disk an extra rotation step.',
    chaocipher_adjustable_cut: 'Chaocipher\'s exact two-disk lookup and rotation rule, but the splice\'s reinsertion point - always position 13 (diametrically opposite) in Byrne\'s design - is a chosen key parameter (1-24) instead of a fixed constant. Cut position 13 is mathematically identical to real Chaocipher.',
    chaocipher_double_splice: 'Chaocipher\'s exact two-disk lookup and permutation rule, applied twice per letter instead of once - "scramble it twice for extra security."',
    move_to_front: 'A single keyed alphabet substitution table: each plaintext letter’s current position (0-25) is the ciphertext, then that letter moves to the very front of the alphabet, so frequently-used letters drift toward the front and the effective shift changes with every letter.',
    move_to_back: 'Like Move-to-Front, but the used letter moves to the very back of the alphabet instead of the front - frequently-used letters drift toward the back, and an immediately-repeated letter always encrypts to ’Z’.',
    dynamic_substitution: 'Terry Ritter’s "Dynamic Substitution Combiner" (1990): a keyed substitution table maps each plaintext letter to a ciphertext letter, then swaps the entry it just used with the entry at a position given by a second, independent keyword (cycling like a repeating key) - so the table keeps re-arranging itself as it goes, one exchange per letter.',
    autokey: 'A short primer keyword starts the key stream; after that, the key stream continues with the plaintext itself.',
    columnar_transposition: 'Plaintext is written into rows under a keyword; columns are read off in the keyword’s alphabetical order. Keyword letters must be distinct.',
    double_columnar_transposition: 'Columnar transposition applied twice, once with each keyword.',
    rail_fence: 'Plaintext is written in a zigzag across N rails and read off rail by rail.',
    myszkowski: 'Like columnar transposition, but the keyword may repeat letters; columns sharing a rank are read together, row by row.',
    adfgx: 'Each letter (I/J merged) is replaced by a 2-letter A/D/F/G/X coordinate pair from a keyed 5x5 square, then the whole coordinate string is columnar-transposed.',
    adfgvx: 'Like ADFGX but with a keyed 6x6 square (26 letters + 10 digits) and A/D/F/G/V/X coordinates.',
    bifid: 'Letters are plotted on a keyed 5x5 Polybius square (I/J merged); row and column coordinates are written out, then re-paired to produce new letters. Period 0 = whole message as one block.',
    trifid: 'Like Bifid but with a keyed 3x3x3 cube (26 letters + a filler symbol "#", which can legitimately appear in ciphertext).',
    quagmire1: 'Keyed plaintext alphabet run against a straight ciphertext alphabet, indexed by an indicator (cycle) word.',
    quagmire2: 'Straight plaintext alphabet run against a keyed ciphertext alphabet, indexed by an indicator word.',
    quagmire3: 'The same keyed alphabet is used for both plaintext and ciphertext (this is the system used for Kryptos K1 and K2).',
    quagmire4: 'Independent keyed alphabets for plaintext and ciphertext, indexed by an indicator word.',
    running_key: 'Like Vigenere, but the key is a long, non-repeating passage of text (here, sampled from a different corpus excerpt) at least as long as the plaintext. Both alphabets are straight (unkeyed); see Running Key I-IV for keyed-alphabet variants.',
    running_key_aca: 'The ACA "Cryptogram" Running Key: one passage is split in half; the first half (never transmitted) keys the second half via straight Vigenere. In generation mode the key is sourced as the text immediately preceding the plaintext in the same corpus source, so key + plaintext read as one continuous passage.',
    running_key1: 'Like Quagmire I (keyed plaintext alphabet, straight ciphertext alphabet), but the indicator is a long, non-repeating running key text (sampled from a different corpus excerpt) instead of a short cycling word.',
    running_key2: 'Like Quagmire II (straight plaintext alphabet, keyed ciphertext alphabet), but the indicator is a long, non-repeating running key text instead of a short cycling word.',
    running_key3: 'Like Quagmire III (the same keyed alphabet for both plaintext and ciphertext), but the indicator is a long, non-repeating running key text instead of a short cycling word.',
    running_key4: 'Like Quagmire IV (independent keyed alphabets for plaintext and ciphertext), but the indicator is a long, non-repeating running key text instead of a short cycling word.',
    running_key_transposition: 'Two-layer cipher: (straight-alphabet) Running Key encryption first, then the result is transposed (simple periodic, or keyword-based columnar).',
    transposition_running_key: 'Two-layer cipher: a transposition (simple periodic, or keyword-based columnar) first, then the transposed text is encrypted with (straight-alphabet) Running Key.',
    vigenere: 'Polyalphabetic shift cipher: C = P + K (mod 26), key repeats.',
    enigma: 'Simulated Wehrmacht Enigma I: 3 rotors (choice of I-V), ring settings, initial positions, reflector B/C, and an optional plugboard.',
    beaufort: 'Self-reciprocal variant: C = K - P (mod 26); the same operation decrypts.',
    porta: 'Self-reciprocal polyalphabetic cipher using 13 reciprocal alphabets selected by key-letter pairs (AB, CD, ... YZ).',
    playfair: 'Digraph substitution using a keyed 5x5 square (I/J merged); row/column/rectangle rules encrypt letter pairs.',
    hill: 'Linear algebra cipher: blocks of 2 or 3 letters are multiplied by an invertible matrix mod 26.',
    scytale: 'Plaintext is written across N columns and read down them in order — equivalent to columnar transposition with an unscrambled column order.',
    solitaire: 'Bruce Schneier’s Solitaire (a.k.a. Pontifex, from Cryptonomicon): a 54-card deck (with 2 jokers) generates a keystream by moving the jokers, cutting around them, and cutting by the bottom card’s value, then reading off an output card; that keystream is added to the plaintext letter by letter.',
    mirdek: 'Paul Crowley’s Mirdek: two 26-card piles (one per colour) are cut and dealt through each other during setup and encryption; each plaintext letter is found by dealing cards onto two alternating piles, and how many cards it took becomes the ciphertext letter. Ciphertext is 25 letters longer than the plaintext (a random initialization vector is prepended).',
    periodic_transposition: 'Reads the plaintext starting at position 0, jumping a fixed interval at a time (wrapping around); when that walk closes back on its own starting point, the next walk starts at the lowest not-yet-visited position, and so on. Popularly (if imprecisely) described as how to solve Kryptos K3 (“count off every 192nd letter”) — the real K3 mechanism is Transposition: Inscription+Rotation, below.',
    inscription_rotation_transposition: 'Kryptos K3’s actual mechanism: the plaintext is written into a grid, that grid is rotated 90/180/270° clockwise or counterclockwise, the rotated letters are inscribed into a second grid, which is itself rotated — reading the final grid off produces the ciphertext. K3 itself uses a 42x8 grid rotated 90° CW, inscribed into 14x24, rotated 90° CW again.',
  };

  let currentCipherId = CIPHER_ORDER[0];
  let currentDirection = 'encrypt';

  // ---------------------------------------------------------------------
  // Cipher select + hint
  // ---------------------------------------------------------------------
  const cipherSelect = document.getElementById('cipherSelect');
  CIPHER_ORDER.forEach((id) => {
    if (!CIPHERS[id]) return;
    const opt = document.createElement('option');
    opt.value = id;
    opt.textContent = CIPHERS[id].label;
    cipherSelect.appendChild(opt);
  });
  cipherSelect.value = currentCipherId;
  cipherSelect.addEventListener('change', () => {
    currentCipherId = cipherSelect.value;
    renderKeyFields();
    document.getElementById('outputText').value = '';
    hideError();
  });

  // ---------------------------------------------------------------------
  // Mode tabs (manual vs generate)
  // ---------------------------------------------------------------------
  const tabBtns = document.querySelectorAll('.tab-btn');
  const modePanels = {
    manual: document.getElementById('manualPanel'),
    generate: document.getElementById('generatePanel'),
    bulk: document.getElementById('bulkPanel'),
    visualize: document.getElementById('visualizePanel'),
  };
  tabBtns.forEach((btn) => {
    btn.addEventListener('click', () => {
      tabBtns.forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      const mode = btn.dataset.mode;
      Object.keys(modePanels).forEach((m) => {
        if (modePanels[m]) modePanels[m].hidden = m !== mode;
      });
    });
  });

  // ---------------------------------------------------------------------
  // Manual encrypt / decrypt
  // ---------------------------------------------------------------------
  const keyFieldsEl = document.getElementById('keyFields');
  const inputLabel = document.getElementById('inputLabel');
  const inputText = document.getElementById('inputText');
  const outputText = document.getElementById('outputText');
  const manualError = document.getElementById('manualError');

  document.querySelectorAll('input[name="direction"]').forEach((radio) => {
    radio.addEventListener('change', (e) => {
      currentDirection = e.target.value;
      inputLabel.textContent = currentDirection === 'encrypt' ? 'Plaintext' : 'Ciphertext';
      outputText.value = '';
      hideError();
    });
  });

  function renderKeyFields() {
    const def = CIPHERS[currentCipherId];
    keyFieldsEl.innerHTML = '';
    def.fields.forEach((f) => {
      const wrap = document.createElement('label');
      wrap.className = 'field';
      const span = document.createElement('span');
      span.textContent = f.label;
      wrap.appendChild(span);
      let input;
      if (f.type === 'textarea') {
        input = document.createElement('textarea');
        input.rows = 2;
      } else {
        input = document.createElement('input');
        input.type = f.type === 'number' ? 'number' : 'text';
        if (f.min !== undefined) input.min = f.min;
        if (f.max !== undefined) input.max = f.max;
      }
      input.dataset.fieldName = f.name;
      input.placeholder = f.placeholder || '';
      wrap.appendChild(input);
      keyFieldsEl.appendChild(wrap);
    });
    document.getElementById('cipherHint').textContent = CIPHER_HINTS[currentCipherId] || '';
  }

  function readFieldValues() {
    const values = {};
    keyFieldsEl.querySelectorAll('[data-field-name]').forEach((el) => {
      values[el.dataset.fieldName] = el.value;
    });
    return values;
  }

  function writeFieldValues(values) {
    keyFieldsEl.querySelectorAll('[data-field-name]').forEach((el) => {
      const name = el.dataset.fieldName;
      if (values[name] !== undefined) el.value = values[name];
    });
  }

  function showError(msg) { manualError.textContent = msg; manualError.hidden = false; }
  function hideError() { manualError.hidden = true; manualError.textContent = ''; }

  document.getElementById('randomKeyBtn').addEventListener('click', () => {
    const def = CIPHERS[currentCipherId];
    const ptLength = onlyLetters(inputText.value).length || 97;
    const { values } = def.randomKey({ ptLength });
    writeFieldValues(values);
    hideError();
  });

  document.getElementById('runBtn').addEventListener('click', () => {
    hideError();
    const def = CIPHERS[currentCipherId];
    try {
      const key = def.keyFromValues(readFieldValues());
      let raw = inputText.value;
      let normalized;
      if (currentCipherId === 'homophonic_substitution' && currentDirection === 'decrypt') {
        normalized = raw.replace(/[^0-9]/g, '');
      } else {
        normalized = onlyLetters(raw);
      }
      if (!normalized) throw new Error(`Please enter some ${currentDirection === 'encrypt' ? 'plaintext' : 'ciphertext'}.`);
      const result = currentDirection === 'encrypt' ? def.encrypt(normalized, key) : def.decrypt(normalized, key);
      outputText.value = result;
    } catch (e) {
      outputText.value = '';
      showError(e.message || String(e));
    }
  });

  renderKeyFields();
  inputLabel.textContent = 'Plaintext';

  // ---------------------------------------------------------------------
  // Length-mode toggle (fixed target length vs. a min/max range), shared
  // between the single-cipher Generate panel and the Bulk Generate panel -
  // each gets its own instance (own radio group name and field ids) since
  // they're independent forms, but both read out through the same
  // getLengthSpec() shape that generator.js expects: a plain number for a
  // fixed target, or { min, max } for a range.
  // ---------------------------------------------------------------------
  function initLengthModeToggle({ radioName, targetFieldId, minFieldId, maxFieldId, targetInputId, minInputId, maxInputId }) {
    const radios = document.querySelectorAll(`input[name="${radioName}"]`);
    const targetField = document.getElementById(targetFieldId);
    const minField = document.getElementById(minFieldId);
    const maxField = document.getElementById(maxFieldId);
    const targetInput = document.getElementById(targetInputId);
    const minInput = document.getElementById(minInputId);
    const maxInput = document.getElementById(maxInputId);
    let mode = 'fixed';
    radios.forEach((radio) => {
      radio.addEventListener('change', (e) => {
        mode = e.target.value;
        targetField.hidden = mode !== 'fixed';
        minField.hidden = mode !== 'range';
        maxField.hidden = mode !== 'range';
      });
    });
    return {
      // Throws a plain Error with a user-facing message on invalid input.
      getLengthSpec() {
        if (mode === 'range') {
          const min = parseInt(minInput.value, 10);
          const max = parseInt(maxInput.value, 10);
          if (!Number.isInteger(min) || min < 1) throw new Error('Min length must be a positive integer.');
          if (!Number.isInteger(max) || max < min) throw new Error('Max length must be an integer >= min length.');
          return { min, max };
        }
        const target = parseInt(targetInput.value, 10);
        if (!Number.isInteger(target) || target < 1) throw new Error('Target length must be a positive integer.');
        return target;
      },
    };
  }

  // ---------------------------------------------------------------------
  // Generation mode
  // ---------------------------------------------------------------------
  const lengthMode = initLengthModeToggle({
    radioName: 'lengthMode',
    targetFieldId: 'targetLengthField', minFieldId: 'minLengthField', maxFieldId: 'maxLengthField',
    targetInputId: 'targetLength', minInputId: 'minLength', maxInputId: 'maxLength',
  });
  const quantityInput = document.getElementById('quantity');
  const generateBtn = document.getElementById('generateBtn');
  const cancelBtn = document.getElementById('cancelBtn');
  const exportCsvBtn = document.getElementById('exportCsvBtn');
  const genProgress = document.getElementById('genProgress');
  const progressFill = document.getElementById('progressFill');
  const progressText = document.getElementById('progressText');
  const genSummary = document.getElementById('genSummary');
  const resultsBody = document.getElementById('resultsBody');
  const prevPageBtn = document.getElementById('prevPage');
  const nextPageBtn = document.getElementById('nextPage');
  const pageInput = document.getElementById('pageInput');
  const pageCountEl = document.getElementById('pageCount');
  const pageSizeSelect = document.getElementById('pageSize');

  let allResults = [];
  let currentPage = 1;
  let cancelled = false;

  function truncate(s, n) { return s.length > n ? s.slice(0, n) + '…' : s; }

  function renderPage() {
    const pageSize = parseInt(pageSizeSelect.value, 10);
    const pageCount = Math.max(1, Math.ceil(allResults.length / pageSize));
    currentPage = Math.min(Math.max(1, currentPage), pageCount);
    pageInput.value = currentPage;
    pageCountEl.textContent = pageCount;
    prevPageBtn.disabled = currentPage <= 1;
    nextPageBtn.disabled = currentPage >= pageCount;

    const start = (currentPage - 1) * pageSize;
    const rows = allResults.slice(start, start + pageSize);
    resultsBody.innerHTML = '';
    for (const r of rows) {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td class="col-idx">${r.index}</td>
        <td>${escapeHtml(r.cipherLabel)}</td>
        <td class="cell-key mono">${escapeHtml(r.keyInfo)}</td>
        <td class="cell-cipher mono">${escapeHtml(truncate(r.ciphertext, 220))}</td>
        <td class="cell-cipher">${escapeHtml(truncate(r.plaintextWithSpaces, 220))}</td>
        <td class="col-len">${r.ciphertext.length}</td>
      `;
      resultsBody.appendChild(tr);
    }
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  prevPageBtn.addEventListener('click', () => { currentPage--; renderPage(); });
  nextPageBtn.addEventListener('click', () => { currentPage++; renderPage(); });
  pageInput.addEventListener('change', () => { currentPage = parseInt(pageInput.value, 10) || 1; renderPage(); });
  pageSizeSelect.addEventListener('change', () => { currentPage = 1; renderPage(); });

  generateBtn.addEventListener('click', () => {
    let lengthSpec;
    try { lengthSpec = lengthMode.getLengthSpec(); } catch (e) { alert(e.message); return; }
    const quantity = parseInt(quantityInput.value, 10);
    if (!Number.isInteger(quantity) || quantity < 1) { alert('Quantity must be a positive integer.'); return; }
    if (quantity > 5000 && !confirm(`Generate ${quantity} ciphers? This may take a little while.`)) return;

    cancelled = false;
    allResults = [];
    currentPage = 1;
    resultsBody.innerHTML = '';
    genSummary.textContent = '';
    exportCsvBtn.disabled = true;
    generateBtn.disabled = true;
    cancelBtn.hidden = false;
    genProgress.hidden = false;
    progressFill.style.width = '0%';
    progressText.textContent = `0 / ${quantity}`;

    window.CipherGenerator.generateCiphersAsync({
      cipherId: currentCipherId,
      lengthSpec,
      quantity,
      isCancelled: () => cancelled,
      onProgress: (done, total, produced) => {
        const pct = Math.round((done / total) * 100);
        progressFill.style.width = pct + '%';
        progressText.textContent = `${done} / ${total}`;
      },
      onDone: (results, skipped, wasCancelled) => {
        allResults = results;
        genProgress.hidden = true;
        generateBtn.disabled = false;
        cancelBtn.hidden = true;
        exportCsvBtn.disabled = results.length === 0;
        genSummary.textContent = wasCancelled
          ? `Cancelled. ${results.length} ciphers generated before stopping.`
          : `Generated ${results.length} ciphers` + (skipped ? ` (${skipped} skipped: could not find a plaintext that reaches the target ciphertext length).` : '.');
        renderPage();
      },
      onError: (e) => {
        genProgress.hidden = true;
        generateBtn.disabled = false;
        cancelBtn.hidden = true;
        genSummary.textContent = 'Error: ' + e.message;
      },
    });
  });

  cancelBtn.addEventListener('click', () => { cancelled = true; });

  // Triggers a browser download of `csv` as `filename`, via a throwaway
  // Blob URL + <a download> - shared by the single-cipher Export CSV
  // button and Bulk Generate's per-type/combined downloads below.
  function downloadCsv(csv, filename) {
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  }
  function timestamp() { return new Date().toISOString().replace(/[:.]/g, '-'); }

  exportCsvBtn.addEventListener('click', () => {
    if (allResults.length === 0) return;
    downloadCsv(window.CipherGenerator.resultsToCsv(allResults), `ciphers_${currentCipherId}_${timestamp()}.csv`);
  });

  // ---------------------------------------------------------------------
  // Bulk Generate mode: runs the same generation engine for every
  // registered cipher type in turn, targeting the same length spec, and
  // downloads one CSV per type as soon as that type finishes (plus makes a
  // combined CSV of everything available once the whole run completes).
  // ---------------------------------------------------------------------
  const bulkLengthMode = initLengthModeToggle({
    radioName: 'bulkLengthMode',
    targetFieldId: 'bulkTargetLengthField', minFieldId: 'bulkMinLengthField', maxFieldId: 'bulkMaxLengthField',
    targetInputId: 'bulkTargetLength', minInputId: 'bulkMinLength', maxInputId: 'bulkMaxLength',
  });
  const bulkQuantityInput = document.getElementById('bulkQuantity');
  const bulkGenerateBtn = document.getElementById('bulkGenerateBtn');
  const bulkCancelBtn = document.getElementById('bulkCancelBtn');
  const bulkDownloadAllBtn = document.getElementById('bulkDownloadAllBtn');
  const bulkProgress = document.getElementById('bulkProgress');
  const bulkProgressFill = document.getElementById('bulkProgressFill');
  const bulkProgressText = document.getElementById('bulkProgressText');
  const bulkSummary = document.getElementById('bulkSummary');
  const bulkResultsBody = document.getElementById('bulkResultsBody');
  document.getElementById('bulkCipherCount').textContent = CIPHER_ORDER.length;

  let bulkCancelled = false;
  let bulkAllResults = []; // flattened across every cipher type, for the combined CSV
  let bulkRowByCipher = {};

  bulkGenerateBtn.addEventListener('click', () => {
    let lengthSpec;
    try { lengthSpec = bulkLengthMode.getLengthSpec(); } catch (e) { alert(e.message); return; }
    const quantity = parseInt(bulkQuantityInput.value, 10);
    if (!Number.isInteger(quantity) || quantity < 1) { alert('Quantity must be a positive integer.'); return; }
    const totalTypes = CIPHER_ORDER.length;
    if (!confirm(`Generate ${quantity} ciphers for each of ${totalTypes} cipher types (${quantity * totalTypes} total), downloading one CSV per type as it finishes?`)) return;

    bulkCancelled = false;
    bulkAllResults = [];
    bulkRowByCipher = {};
    bulkResultsBody.innerHTML = '';
    bulkSummary.textContent = '';
    bulkDownloadAllBtn.disabled = true;
    bulkGenerateBtn.disabled = true;
    bulkCancelBtn.hidden = false;
    bulkProgress.hidden = false;
    bulkProgressFill.style.width = '0%';
    bulkProgressText.textContent = `0 / ${totalTypes} cipher types`;

    CIPHER_ORDER.forEach((id) => {
      const tr = document.createElement('tr');
      tr.innerHTML = `<td>${escapeHtml(CIPHERS[id].label)}</td><td class="col-len">–</td><td class="col-len">–</td><td>Waiting…</td>`;
      bulkResultsBody.appendChild(tr);
      bulkRowByCipher[id] = tr;
    });

    const runTs = timestamp();
    window.CipherGenerator.generateBulkAsync({
      cipherIds: CIPHER_ORDER,
      lengthSpec,
      quantity,
      isCancelled: () => bulkCancelled,
      onCipherStart: (cipherId) => {
        const row = bulkRowByCipher[cipherId];
        if (row) row.children[3].textContent = 'Generating…';
      },
      onCipherDone: (cipherId, results, skipped, wasCancelled, index, total) => {
        bulkAllResults = bulkAllResults.concat(results);
        const row = bulkRowByCipher[cipherId];
        if (row) {
          row.children[1].textContent = results.length;
          row.children[2].textContent = skipped;
        }
        if (results.length > 0) {
          downloadCsv(window.CipherGenerator.resultsToCsv(results), `ciphers_${cipherId}_${runTs}.csv`);
          if (row) row.children[3].textContent = 'Downloaded';
        } else if (row) {
          row.children[3].textContent = 'No results';
        }
        const done = index + 1;
        const pct = Math.round((done / total) * 100);
        bulkProgressFill.style.width = pct + '%';
        bulkProgressText.textContent = `${done} / ${total} cipher types`;
      },
      onAllDone: (allByType, wasCancelled) => {
        bulkProgress.hidden = true;
        bulkGenerateBtn.disabled = false;
        bulkCancelBtn.hidden = true;
        bulkDownloadAllBtn.disabled = bulkAllResults.length === 0;
        bulkSummary.textContent = wasCancelled
          ? `Cancelled. ${bulkAllResults.length} ciphers generated across ${allByType.length} cipher types before stopping.`
          : `Done. Generated ${bulkAllResults.length} ciphers across ${allByType.length} cipher types (one CSV downloaded per type).`;
      },
      onError: (e, cipherId) => {
        bulkSummary.textContent = `Error (${cipherId || 'unknown cipher'}): ${e.message}`;
      },
    });
  });

  bulkCancelBtn.addEventListener('click', () => { bulkCancelled = true; });

  bulkDownloadAllBtn.addEventListener('click', () => {
    if (bulkAllResults.length === 0) return;
    downloadCsv(window.CipherGenerator.resultsToCsv(bulkAllResults), `ciphers_all_${timestamp()}.csv`);
  });

  // ---------------------------------------------------------------------
  // Footer stats
  // ---------------------------------------------------------------------
  (function showCorpusStats() {
    const corpora = window.CIPHERGEN_CORPORA || [];
    const words = window.CIPHERGEN_DICTIONARY_TOP80 || [];
    const totalWords = corpora.reduce((acc, c) => acc + c.text.split(' ').length, 0);
    document.getElementById('corpusStats').textContent =
      `${corpora.length} corpus sources loaded (${totalWords.toLocaleString()} words) · ${words.length.toLocaleString()} dictionary keywords available.`;
  })();
})();

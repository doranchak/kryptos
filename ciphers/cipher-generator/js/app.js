// ============================================================================
// UI wiring: cipher selection, manual encrypt/decrypt, and bulk generation
// with a paginated results table + CSV export.
// ============================================================================

(function () {
  'use strict';

  const { CIPHERS, onlyLetters } = window.CipherLib;

  // Dropdown order mirrors the cipher list as specified for this tool.
  const CIPHER_ORDER = [
    'simple_substitution', 'homophonic_substitution', 'autokey',
    'columnar_transposition', 'double_columnar_transposition', 'rail_fence',
    'myszkowski', 'adfgx', 'adfgvx', 'bifid', 'trifid',
    'quagmire1', 'quagmire2', 'quagmire3', 'quagmire4',
    'running_key', 'running_key_aca', 'running_key1', 'running_key2', 'running_key3', 'running_key4',
    'running_key_transposition', 'transposition_running_key',
    'vigenere', 'enigma', 'beaufort', 'porta', 'playfair',
    'hill', 'scytale',
  ];

  const CIPHER_HINTS = {
    simple_substitution: 'Each plaintext letter always maps to the same cipher letter; the cipher alphabet is a fixed permutation of A-Z.',
    homophonic_substitution: 'Each plaintext letter maps to one of several 2-digit codes (00-99), allocated proportional to English letter frequency so the ciphertext distribution is closer to flat. Ciphertext is digits, decoded 2 at a time.',
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
  // Generation mode
  // ---------------------------------------------------------------------
  const targetLengthInput = document.getElementById('targetLength');
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
        <td class="col-len">${r.plaintextNoSpaces.length}</td>
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
    const targetLength = parseInt(targetLengthInput.value, 10);
    const quantity = parseInt(quantityInput.value, 10);
    if (!Number.isInteger(targetLength) || targetLength < 1) { alert('Target length must be a positive integer.'); return; }
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
      targetLength,
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
          : `Generated ${results.length} ciphers` + (skipped ? ` (${skipped} skipped: no matching passage found for the target length).` : '.');
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

  exportCsvBtn.addEventListener('click', () => {
    if (allResults.length === 0) return;
    const csv = window.CipherGenerator.resultsToCsv(allResults);
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    const ts = new Date().toISOString().replace(/[:.]/g, '-');
    a.download = `ciphers_${currentCipherId}_${ts}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 2000);
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

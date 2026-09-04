// ============================================================================
// Visualizer: shows a plaintext/ciphertext pair for the selected cipher and
// lets the user hover (or tap) a letter to see how it connects to the other
// side, which parts of the key were used, and (where the cipher reduces to
// clean arithmetic) the formula with current values filled in.
//
// Reuses the exact internal helpers ciphers.js exports on window.CipherLib
// (keyed-alphabet builders, Polybius/Playfair/Trifid grid builders, columnar
// transposition core, Hill matrix math, Enigma machine) so every mapping and
// highlight shown here is guaranteed to match what encrypt()/decrypt() do.
// ============================================================================

(function (global) {
  'use strict';

  const CL = global.CipherLib;
  const {
    CIPHERS, ALPHABET, mod, letterNum, numLetter, onlyLetters, keyedAlphabet26,
    keyedSymbolSequence, keywordColumnRanks, orderFromRanks, rangeArray,
    buildHomophoneTables, buildPolybiusSquare, buildTrifidCube, buildPlayfairGrid,
    matVecMul, buildEnigmaMachine,
  } = CL;

  // ---------------------------------------------------------------------
  // small DOM helpers
  // ---------------------------------------------------------------------
  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }
  function cell(text) { return el('span', 'viz-cell', text); }

  function invert(out) {
    const inv = new Array(out.length);
    out.forEach((origIdx, j) => { inv[origIdx] = j; });
    return inv;
  }

  // ---------------------------------------------------------------------
  // Permutation trace helpers: mirror the exact rearrangement logic that
  // columnarEncryptRaw / rail_fence / myszkowski use in ciphers.js, but
  // track original indices instead of characters, so we can highlight the
  // exact plaintext<->ciphertext position for any pen-and-paper transposition
  // regardless of length. Verified against CIPHERS[...].encrypt() output.
  // ---------------------------------------------------------------------
  function columnarTrace(n, order) {
    const k = order.length;
    const numRows = Math.ceil(n / k);
    const longCols = n % k === 0 ? k : n % k;
    const colLen = (col) => (col < longCols ? numRows : numRows - 1);
    const grid = Array.from({ length: k }, () => []);
    let pos = 0;
    for (let r = 0; r < numRows; r++) {
      for (let c = 0; c < k; c++) if (r < colLen(c)) grid[c].push(pos++);
    }
    const out = [];
    for (const c of order) out.push(...grid[c]);
    return { out, grid };
  }

  function railFenceTrace(n, rails) {
    rails = Math.min(rails, Math.max(2, n));
    const rows = Array.from({ length: rails }, () => []);
    let row = 0, dir = 1;
    for (let i = 0; i < n; i++) {
      rows[row].push(i);
      if (rails > 1) { if (row === 0) dir = 1; else if (row === rails - 1) dir = -1; row += dir; }
    }
    return { out: rows.flat(), rows };
  }

  function myszkowskiTrace(n, keyword) {
    const letters = keyword.split('');
    const k = letters.length;
    const numRows = Math.ceil(n / k);
    const longCols = n % k === 0 ? k : n % k;
    const colLen = (col) => (col < longCols ? numRows : numRows - 1);
    const grid = Array.from({ length: k }, () => []);
    let pos = 0;
    for (let r = 0; r < numRows; r++) for (let c = 0; c < k; c++) if (r < colLen(c)) grid[c].push(pos++);
    const uniqueSorted = Array.from(new Set(letters)).sort();
    const out = [];
    for (const letterVal of uniqueSorted) {
      const cols = letters.map((ch, i) => (ch === letterVal ? i : -1)).filter((i) => i >= 0);
      const rows = Math.max(...cols.map(colLen));
      for (let r = 0; r < rows; r++) for (const c of cols) if (r < colLen(c)) out.push(grid[c][r]);
    }
    return { out, grid };
  }

  function invArr(M) { const inv = new Array(26); for (let i = 0; i < 26; i++) inv[letterNum(M[i])] = i; return inv; }

  // Column read-order + display info for a parsed transposition sub-key
  // ({mode:'periodic', rank, display} or {mode:'columnar', keyword}), as
  // produced by ciphers.js's parseTranspositionKey / randomTranspositionKey.
  // Reuses columnarTrace above so the index tracking matches exactly what
  // columnarEncryptRaw/columnarDecryptRaw do in ciphers.js.
  function transpositionTraceFor(t, n) {
    const order = t.mode === 'periodic' ? orderFromRanks(t.rank) : orderFromRanks(keywordColumnRanks(t.keyword));
    const { out, grid } = columnarTrace(n, order);
    if (t.mode === 'periodic') {
      const nums = t.display.split(',').map((s) => s.trim());
      return { out, grid, headerFor: (c) => ['col ' + (c + 1), 'key ' + nums[c]], readOrderNote: 'Simple periodic transposition: columns are read off in the order given by the numeric key.' };
    }
    const rank = keywordColumnRanks(t.keyword);
    const letters = t.keyword.split('');
    return { out, grid, headerFor: (c) => [letters[c], 'rank ' + (rank[c] + 1)], readOrderNote: "Columnar transposition: columns are read off in the keyword's alphabetical rank order." };
  }

  // ---------------------------------------------------------------------
  // Generic renderers shared by several adapters
  // ---------------------------------------------------------------------
  function renderColumnGroups(container, groupsData, text, registerHl) {
    const wrap = el('div', 'viz-grid-wrap');
    groupsData.forEach((g) => {
      const colEl = el('div', 'viz-col-group');
      colEl.appendChild(el('div', 'viz-col-header', g.headerLines.join(' · ')));
      g.indices.forEach((origIdx) => {
        const c = cell(text[origIdx]);
        registerHl('cell-' + origIdx, c);
        colEl.appendChild(c);
      });
      wrap.appendChild(colEl);
    });
    container.appendChild(wrap);
  }

  function renderRowGroups(container, groupsData, text, registerHl) {
    groupsData.forEach((g) => {
      const row = el('div', 'viz-strip-row');
      row.appendChild(el('span', 'viz-strip-row-label', g.headerLines.join(' ')));
      g.indices.forEach((origIdx) => {
        const c = cell(text[origIdx]);
        registerHl('cell-' + origIdx, c);
        row.appendChild(c);
      });
      container.appendChild(row);
    });
  }

  function renderAlphabetStrip(container, arr, prefix, registerHl) {
    const row = el('div', 'viz-strip-row');
    arr.forEach((ch, i) => { const c = cell(ch); registerHl(prefix + i, c); row.appendChild(c); });
    container.appendChild(row);
  }

  function renderTabulaRecta(container, registerHl, mode) {
    const wrap = el('div', 'viz-grid-wrap');
    const table = document.createElement('table'); table.className = 'viz-table';
    const thead = document.createElement('thead'); const hr = document.createElement('tr');
    hr.appendChild(el('th', 'viz-corner'));
    for (let p = 0; p < 26; p++) { const th = document.createElement('th'); th.textContent = ALPHABET[p]; registerHl('tcol-' + p, th); hr.appendChild(th); }
    thead.appendChild(hr); table.appendChild(thead);
    const tbody = document.createElement('tbody');
    for (let k = 0; k < 26; k++) {
      const tr = document.createElement('tr');
      const rh = document.createElement('th'); rh.textContent = ALPHABET[k]; registerHl('trow-' + k, rh); tr.appendChild(rh);
      for (let p = 0; p < 26; p++) {
        const val = mode === 'add' ? mod(k + p, 26) : mod(k - p, 26);
        const td = document.createElement('td'); td.textContent = ALPHABET[val];
        registerHl('tcell-' + k + '-' + p, td);
        tr.appendChild(td);
      }
      tbody.appendChild(tr);
    }
    table.appendChild(tbody); wrap.appendChild(table); container.appendChild(wrap);
  }

  const PORTA_PAIR_LABELS = ['AB', 'CD', 'EF', 'GH', 'IJ', 'KL', 'MN', 'OP', 'QR', 'ST', 'UV', 'WX', 'YZ'];
  function renderPortaTable(container, registerHl) {
    const wrap = el('div', 'viz-grid-wrap');
    const table = document.createElement('table'); table.className = 'viz-table';
    const thead = document.createElement('thead'); const hr = document.createElement('tr');
    hr.appendChild(el('th', 'viz-corner'));
    for (let p = 0; p < 26; p++) { const th = document.createElement('th'); th.textContent = ALPHABET[p]; registerHl('pcol-' + p, th); hr.appendChild(th); }
    thead.appendChild(hr); table.appendChild(thead);
    const tbody = document.createElement('tbody');
    for (let g = 0; g < 13; g++) {
      const tr = document.createElement('tr');
      const rh = document.createElement('th'); rh.textContent = PORTA_PAIR_LABELS[g]; registerHl('prow-' + g, rh); tr.appendChild(rh);
      for (let p = 0; p < 26; p++) {
        const val = p < 13 ? 13 + mod(p + g, 13) : mod((p - 13) - g, 13);
        const td = document.createElement('td'); td.textContent = ALPHABET[val];
        registerHl('pcell-' + g + '-' + p, td);
        tr.appendChild(td);
      }
      tbody.appendChild(tr);
    }
    table.appendChild(tbody); wrap.appendChild(table); container.appendChild(wrap);
  }

  function renderPolybiusGrid(container, grid, labels, registerHl) {
    const wrap = el('div', 'viz-grid-wrap');
    const table = document.createElement('table'); table.className = 'viz-table';
    const thead = document.createElement('thead'); const hr = document.createElement('tr');
    hr.appendChild(el('th', 'viz-corner'));
    labels.forEach((lb, c) => { const th = document.createElement('th'); th.textContent = lb; registerHl('pb-col-' + c, th); hr.appendChild(th); });
    thead.appendChild(hr); table.appendChild(thead);
    const tbody = document.createElement('tbody');
    grid.forEach((rowArr, r) => {
      const tr = document.createElement('tr');
      const rh = document.createElement('th'); rh.textContent = labels[r]; registerHl('pb-row-' + r, rh); tr.appendChild(rh);
      rowArr.forEach((ch, c) => { const td = document.createElement('td'); td.textContent = ch || ''; registerHl('pb-cell-' + r + '-' + c, td); tr.appendChild(td); });
      tbody.appendChild(tr);
    });
    table.appendChild(tbody); wrap.appendChild(table); container.appendChild(wrap);
  }

  // ---------------------------------------------------------------------
  // Adapter registry. Each adapter: { build(pt,ct,key)->state,
  // renderKeyPanel(container,state,registerHl), formulaTemplate (string, or
  // fn(state)->string, or null), hoverPt(state,i), hoverCt(state,j) }.
  // hoverPt/hoverCt return { ct?, pt?, extraPt?, extraCt?, keyIds, current }.
  // ---------------------------------------------------------------------
  const ADAPTERS = {};

  function identityHooks(fn) {
    return {
      hoverPt(state, i) { const r = fn(state, i); return Object.assign({ ct: [i] }, r); },
      hoverCt(state, j) { const r = fn(state, j); return Object.assign({ pt: [j] }, r); },
    };
  }

  // ---- Simple substitution ----
  ADAPTERS.simple_substitution = Object.assign({
    build(pt, ct, key) { return { key, pt, ct }; },
    renderKeyPanel(container, state, registerHl) {
      container.appendChild(el('div', 'viz-subheading', 'Plain → Cipher substitution table'));
      const rowP = el('div', 'viz-strip-row'); rowP.appendChild(el('span', 'viz-strip-row-label', 'Plain'));
      const rowC = el('div', 'viz-strip-row'); rowC.appendChild(el('span', 'viz-strip-row-label', 'Cipher'));
      for (let i = 0; i < 26; i++) {
        const cp = cell(ALPHABET[i]); registerHl('sub-' + i, cp); rowP.appendChild(cp);
        const cc = cell(state.key.cipherAlphabet[i]); registerHl('sub-' + i, cc); rowC.appendChild(cc);
      }
      container.appendChild(rowP); container.appendChild(rowC);
    },
    formulaTemplate: "C = S[P]   (S = cipher alphabet, indexed by the plaintext letter's A=0..Z=25 position)",
  }, identityHooks((state, i) => {
    const p = state.pt[i]; const idx = letterNum(p); const c = state.key.cipherAlphabet[idx];
    return { keyIds: [{ id: 'sub-' + idx, cls: 'hl' }], current: `P='${p}' (position ${idx})  →  S[${idx}]='${c}'  →  C='${c}'` };
  }));

  // ---- Homophonic substitution ----
  ADAPTERS.homophonic_substitution = {
    build(pt, ct, key) {
      const { letterToCodes } = buildHomophoneTables(key.keyword);
      return { key, pt, ct, letterToCodes };
    },
    renderKeyPanel(container, state, registerHl) {
      container.appendChild(el('div', 'viz-subheading', 'Codes available per letter'));
      for (const ch of ALPHABET) {
        const row = el('div', 'viz-homophone-row');
        const label = el('span', 'viz-homophone-letter', ch);
        registerHl('homo-line-' + ch, label);
        row.appendChild(label);
        (state.letterToCodes[ch] || []).forEach((code) => {
          const codeStr = String(code).padStart(2, '0');
          const chip = cell(codeStr);
          registerHl('homo-' + ch + '-' + codeStr, chip);
          registerHl('homo-line-' + ch, chip);
          row.appendChild(chip);
        });
        container.appendChild(row);
      }
    },
    formulaTemplate: 'C = a 2-digit code chosen from Codes[P]   (codes allocated per letter, proportional to English letter frequency)',
    hoverPt(state, i) {
      const p = state.pt[i]; const code = state.ct.substr(2 * i, 2);
      return {
        ct: [2 * i, 2 * i + 1],
        keyIds: [{ id: 'homo-line-' + p, cls: 'hl-line' }, { id: 'homo-' + p + '-' + code, cls: 'hl' }],
        current: `P='${p}'  →  codes available: ${(state.letterToCodes[p] || []).map((c) => String(c).padStart(2, '0')).join(', ')}  →  chosen code '${code}'`,
      };
    },
    hoverCt(state, j) {
      const i = Math.floor(j / 2); const p = state.pt[i]; const code = state.ct.substr(2 * i, 2);
      return {
        pt: [i],
        keyIds: [{ id: 'homo-line-' + p, cls: 'hl-line' }, { id: 'homo-' + p + '-' + code, cls: 'hl' }],
        current: `Digit pair at ciphertext positions ${2 * i}-${2 * i + 1} = '${code}'  →  decodes to P='${p}'`,
      };
    },
  };

  // ---- Vigenere-family (vigenere, beaufort, porta, autokey, running_key) ----
  const VIG_FORMULA = {
    vigenere: 'C(i) = P(i) + K(i)   (mod 26)',
    beaufort: 'C(i) = K(i) − P(i)   (mod 26)',
    porta: 'g = ⌊K(i)/2⌋;  C(i) = 13+((P(i)+g) mod 13) if P(i)<13, else (P(i)−13−g) mod 13',
    autokey: 'C(i) = P(i) + K(i)   (mod 26),  K = primer, then the plaintext itself',
    running_key: 'C(i) = P(i) + K(i)   (mod 26),  K = running key text',
  };

  function buildVigenereFamily(kind) {
    return function build(pt, ct, key) {
      const ptLen = pt.length;
      let keystream;
      if (kind === 'autokey') keystream = Array.from({ length: ptLen }, (_, i) => (i < key.primer.length ? key.primer[i] : pt[i - key.primer.length]));
      else if (kind === 'running_key') keystream = key.keyText.slice(0, ptLen).split('');
      else keystream = Array.from({ length: ptLen }, (_, i) => key.keyword[i % key.keyword.length]);
      return { kind, key, pt, ct, ptLen, keystream };
    };
  }

  function vigenereFamilyHoverAt(state, i) {
    const { kind, key, pt, ct, keystream } = state;
    const p = pt[i], c = ct[i], k = keystream[i];
    const pn = letterNum(p), kn = letterNum(k);
    const keyIds = [];
    let current;
    if (kind === 'porta') {
      const g = Math.floor(kn / 2);
      const cn = pn < 13 ? (13 + mod(pn + g, 13)) : mod((pn - 13) - g, 13);
      keyIds.push({ id: 'prow-' + g, cls: 'hl-line' }, { id: 'pcol-' + pn, cls: 'hl-line' }, { id: 'pcell-' + g + '-' + pn, cls: 'hl' });
      current = `P='${p}' (${pn})   K='${k}' (${kn}, group g=${g}, ${pn < 13 ? 'P<13 branch' : 'P≥13 branch'})   →  C=${cn}='${numLetter(cn)}'`;
    } else {
      const cn = kind === 'beaufort' ? mod(kn - pn, 26) : mod(pn + kn, 26);
      const opSymbol = kind === 'beaufort' ? '−' : '+';
      keyIds.push({ id: 'trow-' + kn, cls: 'hl-line' }, { id: 'tcol-' + pn, cls: 'hl-line' }, { id: 'tcell-' + kn + '-' + pn, cls: 'hl' });
      current = `P='${p}' (${pn})   K='${k}' (${kn})   →  C = (${pn}${opSymbol}${kn}) mod 26 = ${cn} = '${numLetter(cn)}'`;
    }
    let extraPt;
    if (kind === 'vigenere' || kind === 'beaufort' || kind === 'porta') keyIds.push({ id: 'kwpos-' + (i % key.keyword.length), cls: 'hl' });
    else if (kind === 'autokey') { if (i < key.primer.length) keyIds.push({ id: 'primerpos-' + i, cls: 'hl' }); else extraPt = [i - key.primer.length]; }
    else if (kind === 'running_key') keyIds.push({ id: 'ktpos-' + i, cls: 'hl' });
    const result = { keyIds, current };
    if (extraPt) result.extraPt = extraPt;
    return result;
  }

  function renderVigenereFamilyPanel(container, state, registerHl) {
    const { kind, key, ptLen } = state;
    if (kind === 'vigenere' || kind === 'beaufort' || kind === 'porta') {
      container.appendChild(el('div', 'viz-subheading', 'Keyword (repeats)'));
      renderAlphabetStrip(container, key.keyword.split(''), 'kwpos-', registerHl);
    } else if (kind === 'autokey') {
      container.appendChild(el('div', 'viz-subheading', 'Primer (then continues with the plaintext itself)'));
      renderAlphabetStrip(container, key.primer.split(''), 'primerpos-', registerHl);
    } else if (kind === 'running_key') {
      container.appendChild(el('div', 'viz-subheading', 'Key text'));
      renderAlphabetStrip(container, key.keyText.slice(0, ptLen).split(''), 'ktpos-', registerHl);
    }
    if (kind === 'porta') {
      container.appendChild(el('div', 'viz-subheading', 'Porta table (13 key-letter-pair groups × plaintext A-Z)'));
      renderPortaTable(container, registerHl);
    } else {
      container.appendChild(el('div', 'viz-subheading', kind === 'beaufort' ? 'Tabula recta (row=key, col=plain, cell=key−plain)' : 'Tabula recta (row=key, col=plain, cell=key+plain)'));
      renderTabulaRecta(container, registerHl, kind === 'beaufort' ? 'sub' : 'add');
    }
  }

  ['vigenere', 'beaufort', 'porta', 'autokey', 'running_key'].forEach((kind) => {
    ADAPTERS[kind] = Object.assign(
      { build: buildVigenereFamily(kind), renderKeyPanel: renderVigenereFamilyPanel, formulaTemplate: VIG_FORMULA[kind] },
      identityHooks(vigenereFamilyHoverAt)
    );
  });

  // ---- Quagmire I - IV ----
  const QUAGMIRE_FORMULA = {
    I: "idx = (K − anchor + M⁻¹[P]) mod 26;  C = straight[idx]   (M = keyed plaintext alphabet, anchor = M-position of 'A')",
    II: 'idx = (M⁻¹[K] + P) mod 26;  C = M[idx]   (M = keyed ciphertext alphabet, P used as its straight A=0..Z=25 value)',
    III: 'idx = (M⁻¹[K] + M⁻¹[P]) mod 26;  C = M[idx]   (M = keyed alphabet, used for both plaintext and ciphertext)',
    IV: 'idx = (M2⁻¹[K] + M1⁻¹[P]) mod 26;  C = M2[idx]',
  };

  function buildQuagmire(variant) {
    return function build(pt, ct, key) {
      const state = { variant, key, pt, ct };
      if (variant === 'IV') {
        state.M1 = keyedAlphabet26(key.keyword1).split(''); state.M1inv = invArr(state.M1);
        state.M2 = keyedAlphabet26(key.keyword2).split(''); state.M2inv = invArr(state.M2);
      } else {
        state.M = keyedAlphabet26(key.keyword1).split(''); state.Minv = invArr(state.M);
        if (variant === 'I') state.anchor = state.Minv[0];
      }
      return state;
    };
  }

  function quagmireHoverAt(state, i) {
    const { variant, key, pt } = state;
    const p = pt[i];
    const ind = key.indicator; const indChar = ind[i % ind.length]; const indPos = i % ind.length;
    const keyIds = [{ id: 'ind-' + indPos, cls: 'hl' }];
    let current;
    if (variant === 'I') {
      const { M, Minv, anchor } = state;
      const posP = Minv[letterNum(p)];
      const kn = letterNum(indChar);
      const idx = mod(kn - anchor + posP, 26);
      keyIds.push({ id: 'M-' + posP, cls: 'hl' }, { id: 'S-' + idx, cls: 'hl' });
      current = `M-position of P='${p}' is ${posP}.  indicator '${indChar}'=${kn}.  anchor(M-pos of 'A')=${anchor}.  idx=(${kn}−${anchor}+${posP}) mod 26=${idx}  →  C='${numLetter(idx)}'`;
    } else if (variant === 'II') {
      const { M, Minv } = state;
      const posK = Minv[letterNum(indChar)];
      const pn = letterNum(p);
      const idx = mod(posK + pn, 26);
      keyIds.push({ id: 'M-' + posK, cls: 'hl' }, { id: 'M-' + idx, cls: 'hl' }, { id: 'S-' + pn, cls: 'hl' });
      current = `indicator '${indChar}' M-position=${posK}.  P='${p}' (${pn}, straight).  idx=(${posK}+${pn}) mod 26=${idx}  →  C=M[${idx}]='${M[idx]}'`;
    } else if (variant === 'III') {
      const { M, Minv } = state;
      const posK = Minv[letterNum(indChar)];
      const posP = Minv[letterNum(p)];
      const idx = mod(posK + posP, 26);
      keyIds.push({ id: 'M-' + posK, cls: 'hl-line' }, { id: 'M-' + posP, cls: 'hl-line' }, { id: 'M-' + idx, cls: 'hl' });
      current = `indicator '${indChar}' M-position=${posK}.  P='${p}' M-position=${posP}.  idx=(${posK}+${posP}) mod 26=${idx}  →  C=M[${idx}]='${M[idx]}'`;
    } else {
      const { M1, M1inv, M2, M2inv } = state;
      const posP1 = M1inv[letterNum(p)];
      const posK2 = M2inv[letterNum(indChar)];
      const idx = mod(posK2 + posP1, 26);
      keyIds.push({ id: 'M1-' + posP1, cls: 'hl' }, { id: 'M2-' + posK2, cls: 'hl' }, { id: 'M2-' + idx, cls: 'hl' });
      current = `P='${p}' M1-position=${posP1}.  indicator '${indChar}' M2-position=${posK2}.  idx=(${posK2}+${posP1}) mod 26=${idx}  →  C=M2[${idx}]='${M2[idx]}'`;
    }
    return { keyIds, current };
  }

  function renderQuagmirePanel(container, state, registerHl) {
    const ind = state.key.indicator;
    if (state.variant === 'IV') {
      container.appendChild(el('div', 'viz-subheading', 'Keyed alphabet M1 (plaintext, from keyword 1)'));
      renderAlphabetStrip(container, state.M1, 'M1-', registerHl);
      container.appendChild(el('div', 'viz-subheading', 'Keyed alphabet M2 (ciphertext, from keyword 2)'));
      renderAlphabetStrip(container, state.M2, 'M2-', registerHl);
    } else if (state.variant === 'III') {
      container.appendChild(el('div', 'viz-subheading', 'Keyed alphabet M (used for both plaintext and ciphertext)'));
      renderAlphabetStrip(container, state.M, 'M-', registerHl);
    } else {
      container.appendChild(el('div', 'viz-subheading', state.variant === 'I' ? 'Keyed alphabet M (plaintext)' : 'Keyed alphabet M (ciphertext)'));
      renderAlphabetStrip(container, state.M, 'M-', registerHl);
      container.appendChild(el('div', 'viz-subheading', state.variant === 'I' ? 'Straight alphabet (ciphertext)' : 'Straight alphabet (plaintext)'));
      renderAlphabetStrip(container, ALPHABET.split(''), 'S-', registerHl);
    }
    container.appendChild(el('div', 'viz-subheading', 'Indicator (cycle) word'));
    renderAlphabetStrip(container, ind.split(''), 'ind-', registerHl);
  }

  [['quagmire1', 'I'], ['quagmire2', 'II'], ['quagmire3', 'III'], ['quagmire4', 'IV']].forEach(([id, variant]) => {
    ADAPTERS[id] = Object.assign(
      { build: buildQuagmire(variant), renderKeyPanel: renderQuagmirePanel, formulaTemplate: QUAGMIRE_FORMULA[variant] },
      identityHooks(quagmireHoverAt)
    );
  });

  // ---- Enigma ----
  function enigmaAllPositions(key, n) {
    const machine = buildEnigmaMachine(key);
    const seq = [];
    for (let i = 0; i < n; i++) { machine.encodeChar('A'); seq.push(machine.getPositions()); }
    return seq;
  }
  function enigmaCommon(state, i) {
    const positions = state.positionsSeq[i].map(numLetter);
    const p = state.pt[i], c = state.ct[i];
    const keyIds = [];
    (state.key.plugboard || []).forEach(([a, b]) => { if (p === a || p === b || c === a || c === b) keyIds.push({ id: 'plug-' + a + b, cls: 'hl' }); });
    return { keyIds, current: `Rotor positions when encoding this letter (after stepping): ${positions.join(' ')}` };
  }
  ADAPTERS.enigma = {
    build(pt, ct, key) { return { pt, ct, key, positionsSeq: enigmaAllPositions(key, pt.length) }; },
    renderKeyPanel(container, state, registerHl) {
      const k = state.key;
      container.appendChild(el('div', 'viz-subheading', 'Configuration'));
      container.appendChild(el('p', 'viz-note', `Rotors: ${k.rotors.join('-')}   Rings: ${k.ringSettings.join('-')}   Start: ${k.initialPositions.join('')}   Reflector: ${k.reflector}`));
      container.appendChild(el('div', 'viz-subheading', 'Plugboard'));
      if (!k.plugboard || !k.plugboard.length) container.appendChild(el('p', 'viz-note', '(none)'));
      else {
        const row = el('div', 'viz-strip-row');
        k.plugboard.forEach(([a, b]) => { const chip = cell(a + b); registerHl('plug-' + a + b, chip); row.appendChild(chip); });
        container.appendChild(row);
      }
      container.appendChild(el('p', 'viz-note', 'Rotors step with every letter typed; hover a letter to see the rotor positions at that step.'));
    },
    formulaTemplate: null,
    hoverPt(state, i) { const r = enigmaCommon(state, i); return { ct: [i], keyIds: r.keyIds, current: r.current }; },
    hoverCt(state, j) { const r = enigmaCommon(state, j); return { pt: [j], keyIds: r.keyIds, current: r.current }; },
  };

  // ---- Transposition family (columnar, double columnar, myszkowski, rail fence, scytale) ----
  function buildTransposition(kind) {
    return function build(pt, ct, key) {
      const n = pt.length;
      const state = { kind, key, pt, ct, n };
      if (kind === 'rail_fence') {
        const { out, rows } = railFenceTrace(n, key.rails);
        state.posMap = out; state.groups = rows; state.groupNoun = 'rail';
        state.headerFor = (r) => ['Rail ' + (r + 1)];
        state.readOrderNote = 'Ciphertext is formed by reading the rails top to bottom.';
      } else if (kind === 'scytale') {
        const order = rangeArray(key.faces);
        const { out, grid } = columnarTrace(n, order);
        state.posMap = out; state.groups = grid; state.groupNoun = 'column';
        state.headerFor = (c) => ['Col ' + (c + 1)];
        state.readOrderNote = 'Columns are read off left to right, in natural order (no keyword scrambling).';
      } else if (kind === 'myszkowski') {
        const { out, grid } = myszkowskiTrace(n, key.keyword);
        state.posMap = out; state.groups = grid; state.groupNoun = 'column';
        const letters = key.keyword.split('');
        const uniqueSorted = Array.from(new Set(letters)).sort();
        const rankOf = {}; uniqueSorted.forEach((ch, r) => { rankOf[ch] = r + 1; });
        state.headerFor = (c) => [letters[c], 'rank ' + rankOf[letters[c]]];
        state.readOrderNote = 'Columns sharing the same rank are read together, row by row, in ascending rank order.';
      } else {
        const rank = keywordColumnRanks(key.keyword);
        const order = orderFromRanks(rank);
        const { out, grid } = columnarTrace(n, order);
        state.posMap = out; state.groups = grid; state.groupNoun = 'column';
        const letters = key.keyword.split('');
        state.headerFor = (c) => [letters[c], 'rank ' + (rank[c] + 1)];
        state.readOrderNote = "Ciphertext is formed by reading columns off in the order shown by each column's rank.";
      }
      state.groupOf = new Array(n);
      state.groups.forEach((arr, g) => arr.forEach((oi) => { state.groupOf[oi] = g; }));
      state.ptToCt = invert(state.posMap);
      return state;
    };
  }

  function renderTranspositionPanel(container, state, registerHl) {
    const heading = state.groupNoun === 'rail' ? 'Rails (fill order, left→right within each rail)' : 'Columns (fill order, top→bottom)';
    container.appendChild(el('div', 'viz-subheading', heading));
    const groupsData = state.groups.map((indices, gi) => ({ headerLines: state.headerFor(gi), indices }));
    if (state.kind === 'rail_fence') renderRowGroups(container, groupsData, state.pt, registerHl);
    else renderColumnGroups(container, groupsData, state.pt, registerHl);
    container.appendChild(el('p', 'viz-note', state.readOrderNote));
  }

  ['columnar_transposition', 'myszkowski', 'scytale', 'rail_fence'].forEach((id) => {
    ADAPTERS[id] = {
      build: buildTransposition(id),
      renderKeyPanel: renderTranspositionPanel,
      formulaTemplate: null,
      hoverPt(state, i) {
        const ctIdx = state.ptToCt[i]; const g = state.groupOf[i];
        return { ct: [ctIdx], keyIds: [{ id: 'cell-' + i, cls: 'hl' }], current: `P(${i})='${state.pt[i]}' is in ${state.groupNoun} ${g + 1} (${state.headerFor(g).join(' ')})  →  ciphertext position ${ctIdx} ('${state.ct[ctIdx]}')` };
      },
      hoverCt(state, j) {
        const origIdx = state.posMap[j]; const g = state.groupOf[origIdx];
        return { pt: [origIdx], keyIds: [{ id: 'cell-' + origIdx, cls: 'hl' }], current: `Ciphertext position ${j} ('${state.ct[j]}') came from plaintext position ${origIdx} ('${state.pt[origIdx]}'), ${state.groupNoun} ${g + 1} (${state.headerFor(g).join(' ')})` };
      },
    };
  });

  // ---- Double columnar transposition (two stages) ----
  ADAPTERS.double_columnar_transposition = {
    build(pt, ct, key) {
      const n = pt.length;
      const rank1 = keywordColumnRanks(key.keyword1), order1 = orderFromRanks(rank1);
      const rank2 = keywordColumnRanks(key.keyword2), order2 = orderFromRanks(rank2);
      const stage1 = columnarTrace(n, order1);
      const stage2 = columnarTrace(n, order2);
      const posMap = stage2.out.map((m) => stage1.out[m]);
      const ptToCt = invert(posMap);
      const stage1Inv = invert(stage1.out);
      const intermediate = stage1.out.map((oi) => pt[oi]).join('');
      return { pt, ct, n, stage1, stage2, posMap, ptToCt, stage1Inv, letters1: key.keyword1.split(''), rank1, letters2: key.keyword2.split(''), rank2, intermediate };
    },
    renderKeyPanel(container, state, registerHl) {
      container.appendChild(el('div', 'viz-subheading', 'Stage 1 — columns under keyword 1 (produces an intermediate string)'));
      const groups1 = state.stage1.grid.map((indices, c) => ({ headerLines: [state.letters1[c], 'rank ' + (state.rank1[c] + 1)], indices }));
      renderColumnGroups(container, groups1, state.pt, (id, elx) => registerHl('s1-' + id, elx));
      container.appendChild(el('div', 'viz-subheading', 'Stage 2 — columns under keyword 2 (reads the intermediate string, produces ciphertext)'));
      const groups2 = state.stage2.grid.map((indices, c) => ({ headerLines: [state.letters2[c], 'rank ' + (state.rank2[c] + 1)], indices }));
      renderColumnGroups(container, groups2, state.intermediate, (id, elx) => registerHl('s2-' + id, elx));
      container.appendChild(el('p', 'viz-note', 'Each stage is a plain columnar transposition; the output of stage 1 becomes the input to stage 2.'));
    },
    formulaTemplate: null,
    hoverPt(state, i) {
      const ctIdx = state.ptToCt[i]; const m = state.stage1Inv[i];
      return { ct: [ctIdx], keyIds: [{ id: 's1-cell-' + i, cls: 'hl' }, { id: 's2-cell-' + m, cls: 'hl' }], current: `P(${i})='${state.pt[i]}'  →  stage 1 places it at intermediate position ${m}  →  stage 2 sends that to ciphertext position ${ctIdx} ('${state.ct[ctIdx]}')` };
    },
    hoverCt(state, j) {
      const origIdx = state.posMap[j]; const m = state.stage2.out[j];
      return { pt: [origIdx], keyIds: [{ id: 's1-cell-' + origIdx, cls: 'hl' }, { id: 's2-cell-' + m, cls: 'hl' }], current: `Ciphertext position ${j} ('${state.ct[j]}') came from intermediate position ${m}, which came from plaintext position ${origIdx} ('${state.pt[origIdx]}')` };
    },
  };

  // ---- Running Key + Transposition / Transposition + Running Key (two-layer) ----
  // `transFirst` = true for "transposition_running_key" (transposition is
  // stage 1, running key is stage 2); false for "running_key_transposition"
  // (running key is stage 1, transposition is stage 2). In both ciphers the
  // transposition's position-permutation (trans.out / its inverse) is
  // identical; only which running-key index feeds a given ciphertext
  // position changes - the destination position's index when transposition
  // runs last, or the source position's index when it runs first.
  function buildComboRKT(transFirst) {
    return function build(pt, ct, key) {
      const n = pt.length;
      const trans = transpositionTraceFor(key.transposition, n);
      const keystream = key.runningKey.keyText.slice(0, n).split('');
      const ptToCt = invert(trans.out);
      let intermediate;
      if (transFirst) intermediate = trans.out.map((oi) => pt[oi]).join('');
      else intermediate = pt.split('').map((p, i) => numLetter(letterNum(p) + letterNum(keystream[i]))).join('');
      return { pt, ct, key, n, trans, keystream, ptToCt, intermediate, transFirst };
    };
  }

  function renderComboRKTPanel(container, state, registerHl) {
    const { trans, transFirst } = state;
    const transHeading = 'Transposition (fill order top→bottom per column)';
    const keyHeading = 'Running key text';
    if (transFirst) {
      container.appendChild(el('div', 'viz-subheading', 'Stage 1 — ' + transHeading + ', reading the plaintext'));
      const groups = trans.grid.map((indices, c) => ({ headerLines: trans.headerFor(c), indices }));
      renderColumnGroups(container, groups, state.pt, (id, elx) => registerHl('tr-' + id, elx));
      container.appendChild(el('p', 'viz-note', trans.readOrderNote));
      container.appendChild(el('div', 'viz-subheading', 'Stage 2 — ' + keyHeading + ' (applied to the transposed text)'));
      renderAlphabetStrip(container, state.keystream, 'kt-', registerHl);
    } else {
      container.appendChild(el('div', 'viz-subheading', 'Stage 1 — ' + keyHeading + ' (applied to the plaintext)'));
      renderAlphabetStrip(container, state.keystream, 'kt-', registerHl);
      container.appendChild(el('div', 'viz-subheading', 'Stage 2 — ' + transHeading + ', reading the running-key output'));
      const groups = trans.grid.map((indices, c) => ({ headerLines: trans.headerFor(c), indices }));
      renderColumnGroups(container, groups, state.intermediate, (id, elx) => registerHl('tr-' + id, elx));
      container.appendChild(el('p', 'viz-note', trans.readOrderNote));
    }
    container.appendChild(el('div', 'viz-subheading', 'Tabula recta (row=key, col=plain, cell=key+plain)'));
    renderTabulaRecta(container, registerHl, 'add');
  }

  function comboRKTHoverAt(state, i, isCtIndex) {
    const { trans, transFirst, keystream, pt, ct } = state;
    const origIdx = isCtIndex ? trans.out[i] : i;
    const ctIdx = isCtIndex ? i : state.ptToCt[i];
    // "tr-cell-<idx>" was registered against `pt` positions when the
    // transposition ran first, or against `intermediate` positions (which
    // share the same index space as `pt`, since running-key-first doesn't
    // move letters) when it ran second - either way, origIdx is correct.
    const keystreamIdx = transFirst ? ctIdx : origIdx;
    const p = pt[origIdx], kch = keystream[keystreamIdx];
    const pn = letterNum(p), kn = letterNum(kch);
    const cn = mod(pn + kn, 26);
    const keyIds = [
      { id: 'kt-' + keystreamIdx, cls: 'hl' },
      { id: 'tr-cell-' + origIdx, cls: 'hl' },
      { id: 'trow-' + kn, cls: 'hl-line' }, { id: 'tcol-' + pn, cls: 'hl-line' }, { id: 'tcell-' + kn + '-' + pn, cls: 'hl' },
    ];
    const stageOrder = transFirst
      ? `transposed to position ${ctIdx}, then keyed with running-key position ${keystreamIdx}`
      : `keyed with running-key position ${keystreamIdx}, then transposed to position ${ctIdx}`;
    const current = `P(${origIdx})='${p}' → ${stageOrder} → K='${kch}' → C = (${pn}+${kn}) mod 26 = ${cn} = '${numLetter(cn)}' at ciphertext position ${ctIdx}`;
    return { pt: [origIdx], ct: [ctIdx], keyIds, current };
  }

  ['running_key_transposition', 'transposition_running_key'].forEach((id) => {
    const transFirst = id === 'transposition_running_key';
    ADAPTERS[id] = {
      build: buildComboRKT(transFirst),
      renderKeyPanel: renderComboRKTPanel,
      formulaTemplate: transFirst
        ? 'Stage 1 (transposition): rearrange plaintext letter positions.  Stage 2 (running key): C(k) = transposed(k) + K(k)   (mod 26)'
        : 'Stage 1 (running key): C0(i) = P(i) + K(i)   (mod 26).  Stage 2 (transposition): rearrange C0 letter positions to get C.',
      hoverPt(state, i) { const r = comboRKTHoverAt(state, i, false); return { ct: r.ct, keyIds: r.keyIds, current: r.current }; },
      hoverCt(state, j) { const r = comboRKTHoverAt(state, j, true); return { pt: r.pt, keyIds: r.keyIds, current: r.current }; },
    };
  });

  // ---- ADFGX / ADFGVX ----
  function buildAdfgxLike(labels, symbolsBase) {
    return function build(pt, ct, key) {
      const size = labels.length;
      const { lookup, grid } = buildPolybiusSquare(key.squareKeyword, symbolsBase, size);
      const rcPerLetter = []; const coordChars = [];
      for (const ch of pt) { const [r, c] = lookup[ch]; rcPerLetter.push([r, c]); coordChars.push(labels[r], labels[c]); }
      const rank = keywordColumnRanks(key.transKeyword);
      const order = orderFromRanks(rank);
      const { out, grid: coordGrid } = columnarTrace(coordChars.length, order);
      return { pt, ct, key, labels, grid, rcPerLetter, coordChars, posMap: out, coordIndexToCtPos: invert(out), coordGrid, letters: key.transKeyword.split(''), rank };
    };
  }
  function renderAdfgxPanel(container, state, registerHl) {
    container.appendChild(el('div', 'viz-subheading', 'Polybius square (keyed by the square keyword)'));
    renderPolybiusGrid(container, state.grid, state.labels, registerHl);
    container.appendChild(el('div', 'viz-subheading', 'Coordinate string, columnar-transposed by the transposition keyword'));
    const groups = state.coordGrid.map((indices, c) => ({ headerLines: [state.letters[c], 'rank ' + (state.rank[c] + 1)], indices }));
    renderColumnGroups(container, groups, state.coordChars, (id, elx) => registerHl('coord-' + id, elx));
  }
  function adfgxHoverPt(state, i) {
    const [r, c] = state.rcPerLetter[i];
    const coordIdx1 = 2 * i, coordIdx2 = 2 * i + 1;
    const ctPos1 = state.coordIndexToCtPos[coordIdx1], ctPos2 = state.coordIndexToCtPos[coordIdx2];
    return {
      ct: [ctPos1, ctPos2],
      keyIds: [{ id: 'pb-row-' + r, cls: 'hl-line' }, { id: 'pb-col-' + c, cls: 'hl-line' }, { id: 'pb-cell-' + r + '-' + c, cls: 'hl' }, { id: 'coord-cell-' + coordIdx1, cls: 'hl' }, { id: 'coord-cell-' + coordIdx2, cls: 'hl' }],
      current: `P='${state.pt[i]}' → square cell (${state.labels[r]},${state.labels[c]}) → coordinate pair '${state.labels[r]}${state.labels[c]}' → after transposition: ciphertext positions ${ctPos1} and ${ctPos2} ('${state.ct[ctPos1]}${state.ct[ctPos2]}')`,
    };
  }
  function adfgxHoverCt(state, j) {
    const coordIdx = state.posMap[j];
    const origLetterIdx = Math.floor(coordIdx / 2);
    const role = coordIdx % 2 === 0 ? 'row label' : 'col label';
    const siblingCoordIdx = coordIdx % 2 === 0 ? coordIdx + 1 : coordIdx - 1;
    const siblingCtPos = state.coordIndexToCtPos[siblingCoordIdx];
    const [r, c] = state.rcPerLetter[origLetterIdx];
    return {
      pt: [origLetterIdx],
      extraCt: [siblingCtPos],
      keyIds: [{ id: 'pb-row-' + r, cls: 'hl-line' }, { id: 'pb-col-' + c, cls: 'hl-line' }, { id: 'pb-cell-' + r + '-' + c, cls: 'hl' }, { id: 'coord-cell-' + coordIdx, cls: 'hl' }, { id: 'coord-cell-' + siblingCoordIdx, cls: 'hl' }],
      current: `Ciphertext position ${j} ('${state.ct[j]}') is the ${role} of P(${origLetterIdx})='${state.pt[origLetterIdx]}'; its sibling coordinate is at ciphertext position ${siblingCtPos} ('${state.ct[siblingCtPos]}')`,
    };
  }
  function registerAdfgxLike(id, labels, symbolsBase) {
    ADAPTERS[id] = {
      build: buildAdfgxLike(labels, symbolsBase),
      renderKeyPanel: renderAdfgxPanel,
      formulaTemplate: 'coords(P) = (row,col) in the Polybius square → labels[row]+labels[col], then the coordinate string is columnar-transposed by the transposition keyword',
      hoverPt: adfgxHoverPt,
      hoverCt: adfgxHoverCt,
    };
  }
  registerAdfgxLike('adfgx', ['A', 'D', 'F', 'G', 'X'], keyedSymbolSequence('', ALPHABET.replace('J', '')));
  registerAdfgxLike('adfgvx', ['A', 'D', 'F', 'G', 'V', 'X'], keyedSymbolSequence('', ALPHABET + '0123456789'));

  // ---- Bifid ----
  ADAPTERS.bifid = {
    build(pt, ct, key) {
      const symbols = keyedSymbolSequence('', ALPHABET.replace('J', ''));
      const { lookup, grid } = buildPolybiusSquare(key.keyword, symbols, 5);
      const period = key.period > 0 ? key.period : pt.length;
      const ptContributes = Array.from({ length: pt.length }, () => []);
      const ctContributes = Array.from({ length: ct.length }, () => []);
      let outIdx = 0;
      for (let start = 0; start < pt.length; start += period) {
        const blockLen = Math.min(period, pt.length - start);
        for (let i = 0; i < blockLen; i++, outIdx++) {
          const p1 = 2 * i, p2 = 2 * i + 1;
          const src1 = p1 < blockLen ? { ptIndex: start + p1, role: 'row' } : { ptIndex: start + (p1 - blockLen), role: 'col' };
          const src2 = p2 < blockLen ? { ptIndex: start + p2, role: 'row' } : { ptIndex: start + (p2 - blockLen), role: 'col' };
          ptContributes[src1.ptIndex].push({ outIdx, role: src1.role });
          ptContributes[src2.ptIndex].push({ outIdx, role: src2.role });
          ctContributes[outIdx].push({ ptIndex: src1.ptIndex, role: src1.role }, { ptIndex: src2.ptIndex, role: src2.role });
        }
      }
      return { pt, ct, key, lookup, grid, period, ptContributes, ctContributes };
    },
    renderKeyPanel(container, state, registerHl) {
      container.appendChild(el('div', 'viz-subheading', 'Polybius square (I/J merged)'));
      renderPolybiusGrid(container, state.grid, ['1', '2', '3', '4', '5'], registerHl);
      container.appendChild(el('div', 'viz-subheading', 'Row / column coordinates of each plaintext letter'));
      const rowStrip = el('div', 'viz-strip-row'); rowStrip.appendChild(el('span', 'viz-strip-row-label', 'Row'));
      const colStrip = el('div', 'viz-strip-row'); colStrip.appendChild(el('span', 'viz-strip-row-label', 'Col'));
      for (let i = 0; i < state.pt.length; i++) {
        const [r, c] = state.lookup[state.pt[i]];
        const rc = cell(String(r)); registerHl('bf-row-' + i, rc); rowStrip.appendChild(rc);
        const cc = cell(String(c)); registerHl('bf-col-' + i, cc); colStrip.appendChild(cc);
      }
      container.appendChild(rowStrip); container.appendChild(colStrip);
      container.appendChild(el('p', 'viz-note', `Period = ${state.period}: within each block, row numbers then column numbers are written out, then re-paired two at a time into new coordinates that select the output letters.`));
    },
    formulaTemplate: 'output(k) = square[ seq[2k] ][ seq[2k+1] ],  seq = (row-coords of block) ++ (col-coords of block)',
    hoverPt(state, i) {
      const contribs = state.ptContributes[i];
      const [r, c] = state.lookup[state.pt[i]];
      const keyIds = [{ id: 'pb-row-' + r, cls: 'hl-line' }, { id: 'pb-col-' + c, cls: 'hl-line' }, { id: 'pb-cell-' + r + '-' + c, cls: 'hl' }];
      contribs.forEach((cb) => keyIds.push({ id: 'bf-' + cb.role + '-' + i, cls: 'hl' }));
      const parts = contribs.map((cb) => `its ${cb.role} coordinate feeds output letter #${cb.outIdx + 1} ('${state.ct[cb.outIdx]}')`);
      return { ct: contribs.map((cb) => cb.outIdx), keyIds, current: `P='${state.pt[i]}' at square (row ${r}, col ${c}): ${parts.join('; ')}` };
    },
    hoverCt(state, j) {
      const contribs = state.ctContributes[j];
      const keyIds = [];
      contribs.forEach((cb) => { const [r, c] = state.lookup[state.pt[cb.ptIndex]]; keyIds.push({ id: 'pb-cell-' + r + '-' + c, cls: 'hl' }, { id: 'bf-' + cb.role + '-' + cb.ptIndex, cls: 'hl' }); });
      const parts = contribs.map((cb) => `its ${cb.role} coordinate from P(${cb.ptIndex})='${state.pt[cb.ptIndex]}'`);
      return { pt: contribs.map((cb) => cb.ptIndex), keyIds, current: `Ciphertext letter #${j + 1} ('${state.ct[j]}') is built from: ${parts.join(' and ')}` };
    },
  };

  // ---- Trifid ----
  ADAPTERS.trifid = {
    build(pt, ct, key) {
      const { cube, lookup } = buildTrifidCube(key.keyword);
      const period = key.period > 0 ? key.period : pt.length;
      const ptContributes = Array.from({ length: pt.length }, () => []);
      const ctContributes = Array.from({ length: ct.length }, () => []);
      let outIdx = 0;
      for (let start = 0; start < pt.length; start += period) {
        const blockLen = Math.min(period, pt.length - start);
        for (let i = 0; i < blockLen; i++, outIdx++) {
          const positions = [3 * i, 3 * i + 1, 3 * i + 2];
          positions.forEach((p) => {
            let src;
            if (p < blockLen) src = { ptIndex: start + p, role: 'layer' };
            else if (p < 2 * blockLen) src = { ptIndex: start + (p - blockLen), role: 'row' };
            else src = { ptIndex: start + (p - 2 * blockLen), role: 'col' };
            ptContributes[src.ptIndex].push({ outIdx, role: src.role });
            ctContributes[outIdx].push({ ptIndex: src.ptIndex, role: src.role });
          });
        }
      }
      return { pt, ct, key, cube, lookup, period, ptContributes, ctContributes };
    },
    renderKeyPanel(container, state, registerHl) {
      container.appendChild(el('div', 'viz-subheading', 'Cube (3 layers of a 3×3 grid; "#" is a filler symbol)'));
      const wrap = el('div', 'viz-grid-wrap');
      state.cube.forEach((layer, l) => {
        const layerWrap = el('div', 'viz-col-group');
        layerWrap.appendChild(el('div', 'viz-col-header', 'Layer ' + (l + 1)));
        layer.forEach((rowArr, r) => {
          const row = el('div', 'viz-strip-row');
          rowArr.forEach((ch, c) => { const cc = cell(ch); registerHl('tf-cell-' + l + '-' + r + '-' + c, cc); row.appendChild(cc); });
          layerWrap.appendChild(row);
        });
        wrap.appendChild(layerWrap);
      });
      container.appendChild(wrap);
      container.appendChild(el('div', 'viz-subheading', 'Layer / row / column coordinates of each plaintext letter'));
      ['layer', 'row', 'col'].forEach((roleName, ri) => {
        const strip = el('div', 'viz-strip-row'); strip.appendChild(el('span', 'viz-strip-row-label', roleName));
        for (let i = 0; i < state.pt.length; i++) {
          const coord = state.lookup[state.pt[i]];
          const cc = cell(String(coord[ri])); registerHl('tf-' + roleName + '-' + i, cc); strip.appendChild(cc);
        }
        container.appendChild(strip);
      });
      container.appendChild(el('p', 'viz-note', `Period = ${state.period}: within each block, layer numbers, then row numbers, then column numbers are written out, then re-grouped three at a time into new (layer,row,col) triples that select the output letters.`));
    },
    formulaTemplate: 'output(k) = cube[ seq[3k] ][ seq[3k+1] ][ seq[3k+2] ],  seq = (layers) ++ (rows) ++ (cols) of the block',
    hoverPt(state, i) {
      const contribs = state.ptContributes[i];
      const [l, r, c] = state.lookup[state.pt[i]];
      const keyIds = [{ id: 'tf-cell-' + l + '-' + r + '-' + c, cls: 'hl' }];
      contribs.forEach((cb) => keyIds.push({ id: 'tf-' + cb.role + '-' + i, cls: 'hl' }));
      const parts = contribs.map((cb) => `its ${cb.role} coordinate feeds output letter #${cb.outIdx + 1} ('${state.ct[cb.outIdx]}')`);
      return { ct: contribs.map((cb) => cb.outIdx), keyIds, current: `P='${state.pt[i]}' at cube (layer ${l}, row ${r}, col ${c}): ${parts.join('; ')}` };
    },
    hoverCt(state, j) {
      const contribs = state.ctContributes[j];
      const keyIds = [];
      contribs.forEach((cb) => { const [l, r, c] = state.lookup[state.pt[cb.ptIndex]]; keyIds.push({ id: 'tf-cell-' + l + '-' + r + '-' + c, cls: 'hl' }, { id: 'tf-' + cb.role + '-' + cb.ptIndex, cls: 'hl' }); });
      const parts = contribs.map((cb) => `its ${cb.role} coordinate from P(${cb.ptIndex})='${state.pt[cb.ptIndex]}'`);
      return { pt: contribs.map((cb) => cb.ptIndex), keyIds, current: `Ciphertext letter #${j + 1} ('${state.ct[j]}') is built from: ${parts.join(', ')}` };
    },
  };

  // ---- Playfair ----
  ADAPTERS.playfair = {
    build(pt, ct, key) {
      const { grid, pos } = buildPlayfairGrid(key.keyword);
      const letters = pt.replace(/J/g, 'I').split('');
      const digraphs = [];
      let i = 0;
      while (i < letters.length) {
        const a = letters[i]; const b = letters[i + 1];
        if (b === undefined || a === b) { digraphs.push([{ ch: a, srcIdx: i }, { ch: a === 'X' ? 'Q' : 'X', srcIdx: null }]); i += 1; }
        else { digraphs.push([{ ch: a, srcIdx: i }, { ch: b, srcIdx: i + 1 }]); i += 2; }
      }
      const ptIndexToSlot = new Array(pt.length);
      const rules = [];
      digraphs.forEach(([A, B], k) => {
        if (A.srcIdx != null) ptIndexToSlot[A.srcIdx] = { digraphIndex: k, slot: 0 };
        if (B.srcIdx != null) ptIndexToSlot[B.srcIdx] = { digraphIndex: k, slot: 1 };
        const [ra, ca] = pos[A.ch], [rb, cb] = pos[B.ch];
        rules.push(ra === rb ? 'same row → shift each letter one cell right' : ca === cb ? 'same column → shift each letter one cell down' : 'rectangle → swap columns, keep rows');
      });
      return { pt, ct, key, grid, pos, digraphs, ptIndexToSlot, rules };
    },
    renderKeyPanel(container, state, registerHl) {
      container.appendChild(el('div', 'viz-subheading', 'Playfair square (I/J merged)'));
      const wrap = el('div', 'viz-grid-wrap');
      const table = document.createElement('table'); table.className = 'viz-table';
      const tbody = document.createElement('tbody');
      state.grid.forEach((rowArr, r) => {
        const tr = document.createElement('tr');
        rowArr.forEach((ch, c) => { const td = document.createElement('td'); td.textContent = ch; registerHl('pf-cell-' + r + '-' + c, td); tr.appendChild(td); });
        tbody.appendChild(tr);
      });
      table.appendChild(tbody); wrap.appendChild(table); container.appendChild(wrap);
      container.appendChild(el('p', 'viz-note', 'Rules: same row → shift right; same column → shift down; otherwise → swap columns, keep rows. Double letters and a leftover final letter get a null filler (X, or Q if the letter is already X).'));
    },
    formulaTemplate: null,
    hoverPt(state, i) {
      const slot = state.ptIndexToSlot[i];
      const [A, B] = state.digraphs[slot.digraphIndex];
      const [ra, ca] = state.pos[A.ch], [rb, cb] = state.pos[B.ch];
      const ctIndices = [2 * slot.digraphIndex, 2 * slot.digraphIndex + 1];
      const fillerNote = (A.srcIdx == null || B.srcIdx == null) ? `  (a null filler '${A.srcIdx == null ? A.ch : B.ch}' was inserted here)` : '';
      return { ct: ctIndices, keyIds: [{ id: 'pf-cell-' + ra + '-' + ca, cls: 'hl' }, { id: 'pf-cell-' + rb + '-' + cb, cls: 'hl' }], current: `Digraph '${A.ch}${B.ch}' — ${state.rules[slot.digraphIndex]} → '${state.ct[ctIndices[0]]}${state.ct[ctIndices[1]]}'${fillerNote}` };
    },
    hoverCt(state, j) {
      const digraphIndex = Math.floor(j / 2);
      const [A, B] = state.digraphs[digraphIndex];
      const [ra, ca] = state.pos[A.ch], [rb, cb] = state.pos[B.ch];
      const ptIndices = [A.srcIdx, B.srcIdx].filter((x) => x != null);
      return { pt: ptIndices, keyIds: [{ id: 'pf-cell-' + ra + '-' + ca, cls: 'hl' }, { id: 'pf-cell-' + rb + '-' + cb, cls: 'hl' }], current: `Digraph '${A.ch}${B.ch}' — ${state.rules[digraphIndex]} → '${state.ct[2 * digraphIndex]}${state.ct[2 * digraphIndex + 1]}'` };
    },
  };

  // ---- Hill ----
  function hillBlockInfo(state, b) {
    const n = state.n; const start = b * n;
    const vecLetters = state.padded.slice(start, start + n).split('');
    const vecNums = vecLetters.map(letterNum);
    const outNums = matVecMul(state.key.matrix, vecNums, n);
    return { start, vecLetters, vecNums, outNums, outLetters: outNums.map(numLetter) };
  }
  function hillCurrentText(state, b, highlightRow) {
    const info = hillBlockInfo(state, b);
    const lines = [`Block ${b + 1}: P = [${info.vecLetters.join(',')}] = [${info.vecNums.join(',')}]`];
    for (let r = 0; r < state.n; r++) {
      const terms = [];
      for (let c = 0; c < state.n; c++) terms.push(`${state.key.matrix[r][c]}×${info.vecNums[c]}`);
      lines.push(`C${r} = (${terms.join(' + ')}) mod 26 = ${info.outNums[r]} = '${info.outLetters[r]}'${r === highlightRow ? '  ←' : ''}`);
    }
    return lines.join('\n');
  }
  ADAPTERS.hill = {
    build(pt, ct, key) {
      const n = key.size;
      let padded = pt; while (padded.length % n !== 0) padded += 'X';
      return { pt, ct, key, n, padded };
    },
    renderKeyPanel(container, state, registerHl) {
      container.appendChild(el('div', 'viz-subheading', state.n + '×' + state.n + ' key matrix'));
      const wrap = el('div', 'viz-grid-wrap');
      const table = document.createElement('table'); table.className = 'viz-table';
      const tbody = document.createElement('tbody');
      state.key.matrix.forEach((rowArr, r) => {
        const tr = document.createElement('tr');
        rowArr.forEach((v, c) => {
          const td = document.createElement('td'); td.textContent = v;
          registerHl('hill-row-' + r, td); registerHl('hill-col-' + c, td);
          tr.appendChild(td);
        });
        tbody.appendChild(tr);
      });
      table.appendChild(tbody); wrap.appendChild(table); container.appendChild(wrap);
      if (state.padded.length > state.pt.length) container.appendChild(el('p', 'viz-note', `Plaintext padded with ${state.padded.length - state.pt.length} 'X'(s) to fill the last block of ${state.n}.`));
    },
    formulaTemplate(state) { return `C = M · P  (mod 26)  — processed ${state.n} letters at a time`; },
    hoverPt(state, i) {
      const n = state.n; const b = Math.floor(i / n); const c = i - b * n; const start = b * n;
      return { ct: Array.from({ length: n }, (_, k) => start + k), keyIds: [{ id: 'hill-col-' + c, cls: 'hl-line' }], current: hillCurrentText(state, b, -1) };
    },
    hoverCt(state, j) {
      const n = state.n; const b = Math.floor(j / n); const r = j - b * n; const start = b * n;
      const ptIndices = []; for (let k = 0; k < n; k++) { const idx = start + k; if (idx < state.pt.length) ptIndices.push(idx); }
      return { pt: ptIndices, keyIds: [{ id: 'hill-row-' + r, cls: 'hl-line' }], current: hillCurrentText(state, b, r) };
    },
  };

  // ---------------------------------------------------------------------
  // Built-in sample plaintext + per-cipher sample keys. The plaintext is the
  // (misspelled) K1 solution; the running-key sample is a long public-domain
  // passage; quagmire3's sample is the actual K1/K2 keyword/indicator pair.
  // ---------------------------------------------------------------------
  const DEFAULT_PT_DISPLAY = 'BETWEEN SUBTLE SHADING AND THE ABSENCE OF LIGHT LIES THE NUANCE OF IQLUSION';
  const RUNNING_KEY_SAMPLE = 'FOURSCOREANDSEVENYEARSAGOOURFATHERSBROUGHTFORTHONTHISCONTINENTANEWNATIONCONCEIVEDINLIBERTYANDDEDICATEDTOTHEPROPOSITIONTHATALLMENARECREATEDEQUAL';

  const SAMPLES = {
    simple_substitution: { values: { cipherAlphabet: keyedAlphabet26('KRYPTOS') } },
    homophonic_substitution: { values: { keyword: 'SHADOW' } },
    autokey: { values: { primer: 'KRYPTOS' } },
    columnar_transposition: { values: { keyword: 'ZEBRAS' } },
    double_columnar_transposition: { values: { keyword1: 'ZEBRAS', keyword2: 'CIPHER' } },
    rail_fence: { values: { rails: '4' } },
    myszkowski: { values: { keyword: 'TOMATO' } },
    adfgx: { values: { squareKeyword: 'KRYPTOS', transKeyword: 'GERMANY' } },
    adfgvx: { values: { squareKeyword: 'KRYPTOS', transKeyword: 'GERMANY' } },
    bifid: { values: { keyword: 'MONARCHY', period: '5' } },
    trifid: { values: { keyword: 'FELIX', period: '5' } },
    quagmire1: { values: { keyword1: 'KRYPTOS', indicator: 'PALIMPSEST' } },
    quagmire2: { values: { keyword1: 'ABSCISSA', indicator: 'PALIMPSEST' } },
    quagmire3: { values: { keyword1: 'KRYPTOS', indicator: 'PALIMPSEST' } },
    quagmire4: { values: { keyword1: 'KRYPTOS', keyword2: 'ABSCISSA', indicator: 'PALIMPSEST' } },
    running_key: { values: { keyText: RUNNING_KEY_SAMPLE } },
    running_key_transposition: { values: { keyText: RUNNING_KEY_SAMPLE, transKey: 'ZEBRAS' } },
    transposition_running_key: { values: { transKey: '3,1,4,2', keyText: RUNNING_KEY_SAMPLE } },
    vigenere: { values: { keyword: 'PALIMPSEST' } },
    enigma: { values: { rotors: 'II-V-I', ringSettings: '4-11-22', initialPositions: 'QCM', reflector: 'B', plugboard: 'AB CD' } },
    beaufort: { values: { keyword: 'FORTIFICATION' } },
    porta: { values: { keyword: 'PORTA' } },
    playfair: { values: { keyword: 'MONARCHY' } },
    hill: { values: { size: '2', matrix: '3,3\n2,5' } },
    scytale: { values: { faces: '5' } },
  };

  // ---------------------------------------------------------------------
  // UI wiring
  // ---------------------------------------------------------------------
  const cipherSelect = document.getElementById('cipherSelect');
  const visualizePanel = document.getElementById('visualizePanel');
  const vizKeyFieldsEl = document.getElementById('vizKeyFields');
  const ptInput = document.getElementById('vizPtInput');
  const ctInput = document.getElementById('vizCtInput');
  const ptStripEl = document.getElementById('vizPtStrip');
  const ctStripEl = document.getElementById('vizCtStrip');
  const vizErrorEl = document.getElementById('vizError');
  const vizFormulaTemplateEl = document.getElementById('vizFormulaTemplate');
  const vizFormulaCurrentEl = document.getElementById('vizFormulaCurrent');
  const vizKeyInfoPanel = document.getElementById('vizKeyInfoPanel');
  const vizSampleBtn = document.getElementById('vizSampleBtn');

  if (!cipherSelect || !visualizePanel) return; // defensive: markup not present

  let source = 'pt';
  let currentState = null;
  let pinned = null;
  const FORMULA_PLACEHOLDER = 'Hover (or tap) a plaintext or ciphertext letter to see the current values.';

  function showVizError(msg) { vizErrorEl.textContent = msg; vizErrorEl.hidden = false; }
  function hideVizError() { vizErrorEl.hidden = true; vizErrorEl.textContent = ''; }

  function renderVizKeyFields() {
    const def = CIPHERS[cipherSelect.value];
    vizKeyFieldsEl.innerHTML = '';
    def.fields.forEach((f) => {
      const wrap = document.createElement('label'); wrap.className = 'field';
      const span = document.createElement('span'); span.textContent = f.label; wrap.appendChild(span);
      let input;
      if (f.type === 'textarea') { input = document.createElement('textarea'); input.rows = 2; }
      else { input = document.createElement('input'); input.type = f.type === 'number' ? 'number' : 'text'; if (f.min !== undefined) input.min = f.min; if (f.max !== undefined) input.max = f.max; }
      input.dataset.fieldName = f.name;
      input.placeholder = f.placeholder || '';
      input.addEventListener('input', () => recompute());
      wrap.appendChild(input);
      vizKeyFieldsEl.appendChild(wrap);
    });
  }
  function readVizFieldValues() {
    const values = {};
    vizKeyFieldsEl.querySelectorAll('[data-field-name]').forEach((elx) => { values[elx.dataset.fieldName] = elx.value; });
    return values;
  }
  function writeVizFieldValues(values) {
    vizKeyFieldsEl.querySelectorAll('[data-field-name]').forEach((elx) => { const name = elx.dataset.fieldName; if (values[name] !== undefined) elx.value = values[name]; });
  }

  function renderStrip(container, text, side, groupSize) {
    container.innerHTML = '';
    if (!text) { container.appendChild(el('span', 'viz-strip-placeholder', '(empty)')); return; }
    text.split('').forEach((ch, i) => {
      const span = el('span', 'viz-letter', ch);
      span.dataset.side = side; span.dataset.idx = String(i);
      if (groupSize && (i + 1) % groupSize === 0) span.style.marginRight = '6px';
      container.appendChild(span);
    });
  }

  function clearAll() {
    renderStrip(ptStripEl, '', 'pt');
    renderStrip(ctStripEl, '', 'ct');
    vizKeyInfoPanel.innerHTML = '';
    vizFormulaTemplateEl.textContent = '';
    vizFormulaCurrentEl.textContent = FORMULA_PLACEHOLDER;
    currentState = null;
  }

  function renderKeyPanelFor(state) {
    vizKeyInfoPanel.innerHTML = '';
    state.registry = {};
    const registerHl = (id, element) => { (state.registry[id] = state.registry[id] || []).push(element); };
    const adapter = state.adapter;
    if (!adapter) {
      vizKeyInfoPanel.appendChild(el('p', 'viz-note', 'No key visualization is available yet for this cipher.'));
      vizFormulaTemplateEl.textContent = '';
      vizFormulaCurrentEl.textContent = FORMULA_PLACEHOLDER;
      return;
    }
    state.adapterState = adapter.build(state.pt, state.ct, state.key);
    adapter.renderKeyPanel(vizKeyInfoPanel, state.adapterState, registerHl);
    const tmpl = typeof adapter.formulaTemplate === 'function' ? adapter.formulaTemplate(state.adapterState) : adapter.formulaTemplate;
    vizFormulaTemplateEl.textContent = tmpl || '';
    vizFormulaCurrentEl.textContent = FORMULA_PLACEHOLDER;
  }

  function recompute() {
    hideVizError();
    const id = cipherSelect.value;
    const def = CIPHERS[id];
    if (!def) return;
    let key;
    try { key = def.keyFromValues(readVizFieldValues()); }
    catch (e) { showVizError(e.message || String(e)); clearAll(); return; }

    let pt, ct;
    try {
      if (source === 'pt') {
        pt = onlyLetters(ptInput.value);
        if (!pt) throw new Error('Please enter some plaintext.');
        ct = def.encrypt(pt, key);
        ctInput.value = ct;
      } else {
        const normalized = id === 'homophonic_substitution' ? ctInput.value.replace(/[^0-9]/g, '') : onlyLetters(ctInput.value);
        if (!normalized) throw new Error('Please enter some ciphertext.');
        ct = normalized;
        pt = def.decrypt(ct, key);
        ptInput.value = pt;
      }
    } catch (e) {
      showVizError(e.message || String(e));
      clearAll();
      return;
    }

    currentState = { id, def, key, pt, ct, adapter: ADAPTERS[id] };
    pinned = null;
    renderStrip(ptStripEl, pt, 'pt');
    renderStrip(ctStripEl, ct, 'ct', id === 'homophonic_substitution' ? 2 : undefined);
    renderKeyPanelFor(currentState);
  }

  function clearHighlight() {
    document.querySelectorAll('#visualizePanel .viz-letter.hl-active, #visualizePanel .viz-letter.hl-linked, #visualizePanel .viz-letter.hl-key-source')
      .forEach((elx) => elx.classList.remove('hl-active', 'hl-linked', 'hl-key-source'));
    if (currentState && currentState.registry) {
      Object.values(currentState.registry).forEach((arr) => arr.forEach((elx) => elx.classList.remove('hl', 'hl-soft', 'hl-line')));
    }
    if (vizFormulaCurrentEl) vizFormulaCurrentEl.textContent = FORMULA_PLACEHOLDER;
  }

  function applyHighlight(side, idx) {
    if (!currentState || !currentState.adapter) return;
    clearHighlight();
    const activeSpan = (side === 'pt' ? ptStripEl : ctStripEl).querySelector('.viz-letter[data-idx="' + idx + '"]');
    if (activeSpan) activeSpan.classList.add('hl-active');
    const info = side === 'pt' ? currentState.adapter.hoverPt(currentState.adapterState, idx) : currentState.adapter.hoverCt(currentState.adapterState, idx);
    if (!info) return;
    (info.ct || []).forEach((j) => { const s = ctStripEl.querySelector('.viz-letter[data-idx="' + j + '"]'); if (s) s.classList.add('hl-linked'); });
    (info.pt || []).forEach((i) => { const s = ptStripEl.querySelector('.viz-letter[data-idx="' + i + '"]'); if (s) s.classList.add('hl-linked'); });
    (info.extraPt || []).forEach((i) => { const s = ptStripEl.querySelector('.viz-letter[data-idx="' + i + '"]'); if (s) s.classList.add('hl-key-source'); });
    (info.extraCt || []).forEach((j) => { const s = ctStripEl.querySelector('.viz-letter[data-idx="' + j + '"]'); if (s) s.classList.add('hl-key-source'); });
    (info.keyIds || []).forEach(({ id, cls }) => { (currentState.registry[id] || []).forEach((elx) => elx.classList.add(cls || 'hl')); });
    if (vizFormulaCurrentEl) vizFormulaCurrentEl.textContent = info.current || FORMULA_PLACEHOLDER;
  }

  function wireStripEvents(container, side) {
    container.addEventListener('pointerover', (e) => {
      if (pinned) return;
      const t = e.target.closest('.viz-letter');
      if (!t) return;
      applyHighlight(side, parseInt(t.dataset.idx, 10));
    });
    container.addEventListener('pointerout', (e) => {
      if (pinned) return;
      const t = e.target.closest('.viz-letter');
      if (!t) return;
      clearHighlight();
    });
    container.addEventListener('click', (e) => {
      const t = e.target.closest('.viz-letter');
      if (!t) return;
      const idx = parseInt(t.dataset.idx, 10);
      if (pinned && pinned.side === side && pinned.idx === idx) { pinned = null; clearHighlight(); }
      else { pinned = { side, idx }; applyHighlight(side, idx); }
    });
  }
  wireStripEvents(ptStripEl, 'pt');
  wireStripEvents(ctStripEl, 'ct');

  ptInput.addEventListener('input', () => { source = 'pt'; recompute(); });
  ctInput.addEventListener('input', () => { source = 'ct'; recompute(); });

  function loadSample() {
    renderVizKeyFields();
    const sample = SAMPLES[cipherSelect.value] || { values: {} };
    writeVizFieldValues(sample.values);
    source = 'pt';
    ptInput.value = DEFAULT_PT_DISPLAY;
    ctInput.value = '';
    hideVizError();
    recompute();
  }
  if (vizSampleBtn) vizSampleBtn.addEventListener('click', loadSample);

  let lastCipherForViz = null;
  function activateVisualizer() {
    if (cipherSelect.value !== lastCipherForViz) { lastCipherForViz = cipherSelect.value; loadSample(); }
  }
  cipherSelect.addEventListener('change', () => {
    if (visualizePanel.hidden) lastCipherForViz = null;
    else activateVisualizer();
  });
  const vizTabBtn = document.querySelector('.tab-btn[data-mode="visualize"]');
  if (vizTabBtn) vizTabBtn.addEventListener('click', activateVisualizer);

  global.CipherVisualizer = { ADAPTERS, SAMPLES };
})(typeof window !== 'undefined' ? window : globalThis);

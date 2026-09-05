# Cipher Generator

A locally-stored, offline HTML+JS tool for manual encrypt/decrypt and bulk
generation of classical pen-and-paper cipher samples, for practice, testing
solvers, or building training/eval sets.

## Running it

Just open [index.html](index.html) in a browser. No server, no build step,
no network access required at runtime — all corpus text and dictionary data
is embedded directly into the page via `js/data/*.js`.

## Features

- **30 cipher types**: simple substitution, homophonic substitution, autokey,
  columnar transposition, double columnar transposition, rail fence,
  Myszkowski transposition, ADFGX, ADFGVX, bifid, trifid, Quagmire I-IV,
  **Running Key**, **Running Key ACA**, **Running Key I-IV**, **running key +
  transposition**, **transposition + running key**, Vigenère, Enigma,
  Beaufort, Porta, Playfair, Hill, scytale.
  - Running Key is the "unkeyed" case: both plaintext and ciphertext
    alphabets are straight A-Z, key = a long, non-repeating passage of text
    at least as long as the plaintext.
  - Running Key ACA is the [ACA "Cryptogram" RUNNING KEY
    variant](https://www.cryptogram.org/downloads/aca.info/ciphers/RunningKey.pdf):
    a single passage is split in half; the first half is never transmitted
    and exists purely as the key for encrypting the second half (same
    straight-Vigenère math as plain Running Key). What makes it the ACA
    variant is that the key is a genuine continuation of the same passage,
    not unrelated text — in generation mode the key is sourced as the text
    immediately preceding the chosen plaintext in the same corpus source
    (falling back to an unrelated excerpt only when the plaintext was
    selected too close to the start of its source to have that much
    preceding context), so key + plaintext read as one continuous passage.
  - Running Key I-IV apply Quagmire I-IV's four plain/cipher-alphabet
    combinations (I: keyed plaintext alphabet; II: keyed ciphertext
    alphabet; III: one keyword keys both, as in Kryptos K1/K2; IV:
    independent keywords key each side) but replace Quagmire's short,
    cycling indicator word with that same kind of running key text — one key
    letter per plaintext letter, never reused.
  - The two running-key-plus-transposition ciphers are two-layer: a
    straight-alphabet Running Key encryption and a transposition step
    (either simple periodic — an explicit numeric column order like
    `3,1,4,2` — or ordinary keyword-based columnar), applied in one order or
    the other. Which sub-type the transposition key field means is
    auto-detected: digits/commas -> simple periodic, letters -> columnar
    keyword.
- **Manual encrypt/decrypt mode**: pick a cipher, fill in (or randomize) its
  key, type plaintext or ciphertext, run it.
- **Generation mode**: pick a target plaintext length (default 97, matching
  Kryptos K4) and a quantity (supports generating thousands at once, chunked
  so the browser tab stays responsive), and the tool will:
  1. Pick a random corpus file.
  2. Pick a random contiguous run of whole words from it whose combined
     letter count (no spaces) exactly matches the target length, rejecting
     runs that don't look like normal English (long repeated-letter runs or
     unusually low letter-frequency entropy).
  3. Generate a random, cipher-appropriate key — keywords are drawn from the
     top 80% (by frequency rank) of `english_words__practicalcryptography_percentile_99.txt`.
  4. Encrypt, and add the row to a paginated results table.
- **CSV export** with columns: cipher type label, key information,
  ciphertext, plaintext without spaces, plaintext with spaces.
- **Visualizer mode**: pick a cipher, load the built-in sample (or type your
  own plaintext/ciphertext), and hover any letter to see exactly how it maps
  to the other side — which key-table cell, alphabet position, transposition
  column, or Polybius/Playfair/Trifid grid cell produced it — plus a formula
  with the current values filled in. For two-layer ciphers (double columnar
  transposition, ADFGX/ADFGVX, and the two running-key-plus-transposition
  ciphers) it shows both stages and traces a letter's position through both.

Note: the target length governs the *plaintext* letter count that gets
selected, not necessarily the final ciphertext length — ciphers that
fractionate or expand text (homophonic substitution, ADFGX, ADFGVX roughly
double it) or pad to a block size (Hill, Playfair) will produce a ciphertext
a little longer than the target.

## Corpora

`corpora/*.txt` holds 273 plaintext sources (~373,000 words total),
normalized to uppercase A-Z letters only, words separated by a single space
(no punctuation, digits, or other symbols):

- **~132 Wikipedia article introductions**, fetched at random via the
  Wikipedia API (`wiki_NNNN_<slug>.txt`).
- **~140 excerpts from 30 public-domain Project Gutenberg ebooks**
  (`gutenberg_<id>_<slug>_NN.txt`), 2-6 excerpts per book sampled evenly
  across its length so a single long novel doesn't dominate the corpus.

Regenerating or extending the corpus:

```bash
python3 scripts/fetch_wikipedia.py --target 100   # fetch more Wikipedia articles
python3 scripts/fetch_gutenberg.py                # fetch/refresh the Gutenberg book list
python3 scripts/build_data.py                      # rebuild js/data/corpora_data.js and dictionary_data.js
```

`build_data.py` also rebuilds `js/data/dictionary_data.js` (the top 80% of
`english_words__practicalcryptography_percentile_99.txt` by frequency rank,
used for random keyword selection) from that source file. Run it after
editing `corpora/` or the dictionary file — `index.html` loads the generated
`js/data/*.js` files, not the raw `.txt` sources, so nothing updates until
you rebuild.

## Code layout

- `js/ciphers.js` — the cipher library: for each cipher, key generation
  (`randomKey`), manual-mode key parsing (`keyFromValues`), `encrypt`,
  `decrypt`, and a `keyInfo` formatter.
- `js/generator.js` — the plaintext-sampling and bulk-generation engine.
- `js/app.js` — UI wiring (cipher/mode selection, manual run, generation
  progress, pagination, CSV export).
- `js/visualizer.js` — the letter-by-letter visualizer: per-cipher adapters
  that reuse ciphers.js's internal helpers (exported on `window.CipherLib`)
  to build the exact same tables/grids/permutations `encrypt()`/`decrypt()`
  use, so highlighting can never drift from the real cipher logic.
- `scripts/test_ciphers.js` — a Node-based self-test: round-trips every
  cipher, and checks exact-match reference vectors for the Quagmire ciphers
  (against the ACA "Cryptogram" reference examples and the real Kryptos
  K1/K2 ciphertexts), Vigenère, Playfair, Rail Fence, Hill, Running Key I-IV
  (see below), and both running-key-plus-transposition ciphers (hand-worked
  vectors). Run with `node scripts/test_ciphers.js`.

## Notes on cipher fidelity

Quagmire I-IV were implemented and verified against the official ACA
("Cryptogram") reference worked examples (`QuagmireI.pdf`-`QuagmireIV.pdf`
from cryptogram.org) plus the real Kryptos K1 and K2 keyword/indicator/
ciphertext triples for Quagmire III — all match exactly (see
`scripts/test_ciphers.js`). Running Key I-IV reuse that same verified
per-letter formula (only the indicator source differs), so they're
cross-checked against those same ACA/Kryptos vectors: for a plaintext no
longer than the indicator word, `indicator[i % len] === indicator[i]` for
every position, so feeding a Running Key variant that same indicator word as
its running key text must reproduce an exact prefix of the matching
Quagmire ciphertext — and it does, exactly. Running Key ACA is checked
against the official ACA worked example (`RunningKey.pdf` from
cryptogram.org) — exact match — plus a check that `generator.js`'s
preceding-text lookup is an exact, contiguous substring of the same corpus
source immediately before the chosen plaintext. Enigma implements the
standard
Wehrmacht Enigma I rotor wirings (I-V), reflectors B/C, ring settings, and
the classic double-step anomaly; it's internally self-reciprocal and
structurally standard, but wasn't checked against an external
known-ciphertext vector.

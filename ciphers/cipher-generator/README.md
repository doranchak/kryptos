# Cipher Generator

A locally-stored, offline HTML+JS tool for manual encrypt/decrypt and bulk
generation of classical pen-and-paper cipher samples, for practice, testing
solvers, or building training/eval sets.

## Running it

Just open [index.html](index.html) in a browser. No server, no build step,
no network access required at runtime — all corpus text and dictionary data
is embedded directly into the page via `js/data/*.js`.

## Features

- **36 cipher types**: simple substitution, homophonic substitution,
  **Chaocipher**, **Move-to-Front substitution**, **Move-to-Back
  substitution**, **Dynamic Substitution**, autokey, columnar transposition,
  double columnar transposition, rail fence, Myszkowski transposition, ADFGX,
  ADFGVX, bifid, trifid, Quagmire I-IV, **Running Key**, **Running Key ACA**,
  **Running Key I-IV**, **running key + transposition**, **transposition +
  running key**, Vigenère, Enigma, Beaufort, Porta, Playfair, Hill, scytale,
  **Solitaire (Pontifex)**, **Mirdek**.
  - Move-to-Front / Move-to-Back substitution: a single keyed 26-letter
    alphabet acts as a self-modifying substitution table. To encrypt
    plaintext letter P, find P's current position in that alphabet (0-25) —
    that position, read straight off A=0..Z=25, is the ciphertext letter —
    then move P to the very front (MTF) or very back (MTB) of the alphabet,
    shifting the letters in between to fill the gap. Frequently-used letters
    drift toward the front (or back), so the effective shift changes with
    every single letter — a "self-organizing list" turned into a cipher.
  - Dynamic Substitution (Terry Ritter, 1990, "The Dynamic Substitution
    Combiner"): a keyed substitution table maps each plaintext letter to a
    ciphertext letter, exactly like ordinary simple substitution — except
    that after every letter, the table entry just used is swapped with the
    table entry at a second position, taken from a separate confusion
    keyword that cycles like a repeating Vigenère key. The confusion keyword
    stands in for Ritter's synchronized pseudo-random "Random In" stream —
    both encrypting and decrypting only need the same two keywords to
    reproduce the identical sequence of swaps, with no separate keystream to
    exchange. The table keeps re-arranging itself one exchange per letter,
    which is Ritter's whole point: the substitution never has a chance to
    settle down long enough for frequency analysis to characterize it.
  - Chaocipher (John F. Byrne): two 26-letter "disks" - a left (ciphertext)
    and right (plaintext) alphabet - that dynamically permute after every
    single letter (each disk rotates to bring the letter just used to
    position 0, then moves one more letter to position 13; the right disk
    takes one extra rotation step first), so the effective substitution
    never repeats.
  - Solitaire, a.k.a. Pontifex (Bruce Schneier, from *Cryptonomicon*): a
    54-card deck (52 cards + 2 distinguishable jokers) generates a keystream
    by moving the jokers down 1 and 2 cards, triple-cutting around them,
    count-cutting by the bottom card's value, then reading off an output
    card by counting from the top card's value (skipping and retrying on a
    joker) - that keystream is added to the plaintext, letter by letter,
    using Solitaire's own 1-26 wraparound (not plain mod-26 addition). Keyed
    by a passphrase (Schneier's "keying method 3": a count-cut by each
    passphrase letter's value, once per letter, before generating any
    keystream).
  - Mirdek (Paul Crowley): two 26-card piles, one per colour, each a
    permutation of A-Z. A counted cut (draw the other pile's top card, cut
    this pile by its 1-26 value) and a letter search (deal cards onto two
    alternating piles until a target letter appears, then reassemble) drive
    setup (initialisation, keying, mixing) and encryption. Each plaintext
    letter is searched for in the left pile after a counted cut; however
    many cards that took (as a letter, A=1) is the ciphertext. Ciphertext is
    always 25 letters longer than the plaintext, since a random 25-letter
    initialization vector is prepended (needed to reconstruct the starting
    "right" pile) - decryption reads it back off the ciphertext itself, so
    only the passphrase needs to be shared out of band.
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
  For Chaocipher it draws both disks as an actual rotating-tab diagram,
  redrawn on every hover to the exact wheel arrangement at that step, with
  the tab used for that letter picked out. For Solitaire and Mirdek it draws
  actual playing-card tiles (red/black, with jokers marked) for the deck (or
  the Left/Right/Discard piles), redrawn on every hover to that letter's
  exact state, with a step-by-step breakdown of the joker moves/cuts (or
  counted cut/letter search) that produced it. For Move-to-Front/Move-to-Back
  it draws the full 26-letter alphabet strip, redrawn on every hover to
  exactly how it stood *before* that letter was looked up, with the used
  position highlighted so the front-ward (or back-ward) drift is visible
  letter by letter. For Dynamic Substitution it draws the substitution table
  as two aligned rows (fixed plain A-Z on top, current cipher image below),
  redrawn on every hover to that letter's exact table state, with the
  plaintext letter's column and its confusion-keyword swap partner's column
  both picked out.

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
standard Wehrmacht Enigma I rotor wirings (I-V), reflectors B/C, ring
settings, and the classic double-step anomaly, and is checked against a real
external vector: `scripts/fixtures/enigma_gillogly.{txt,solution}`, the
well-known "Gillogly" M3 test cipher, decrypts to the exact German plaintext
when given the settings an independent Enigma solver (the "colossus"
project) reported for it. Rotors/rings/positions are entered left to right
(the field labels' stated convention, and the convention colossus's own
report uses) — this KAT is in fact what caught a real bug where the code
silently treated array index 0 as the *rightmost* rotor while the label
claimed "left to right"; see `scripts/test_ciphers.js` for the exact
settings translation. Chaocipher's permutation rule (which position each
disk rotates to the front, and which position gets moved where) was
reverse-engineered by brute-force search against a vector generated by
dcode.gr's Chaocipher tool, then locked in as a permanent KAT in
`scripts/test_ciphers.js` — exact match on both encrypt and decrypt.
Solitaire is checked against all three official worked examples on
[schneier.com/academic/solitaire](https://www.schneier.com/academic/solitaire/)
(an unkeyed deck, and two passphrase-keyed examples) plus that page's own
"DONOTUSEPC" worked arithmetic example — all match exactly, including the
raw (pre-mod-26) keystream card values Schneier's page lists for the unkeyed
case. Mirdek is checked against the complete worked example at
[ciphergoth.org/crypto/mirdek/example.html](https://www.ciphergoth.org/crypto/mirdek/example.html),
which lays out every intermediate pile state for a full initialisation +
9-letter keying + 26-card mixing + 10-letter encryption run; this
implementation reproduces every one of those intermediate states exactly,
not just the final ciphertext (building it against that page's line-by-line
trace is in fact how a real bug in the mixing phase's final pile-swap was
caught and fixed). Move-to-Front and Move-to-Back substitution are not
historically-attested named ciphers with a canonical published reference —
they're a straightforward implementation of the classic "move-to-front"
self-organizing-list transform (well known from data compression, e.g.
Burrows-Wheeler-based compressors) repurposed as a cipher. Correctness is
checked against a small hand-worked vector chosen so the arithmetic is easy
to verify by hand: keyword `ABC` (which keys to a plain, unshifted A-Z
starting alphabet) encrypting `BANANA`, independently derived twice for both
MTF and MTB and locked in as a permanent KAT in `scripts/test_ciphers.js`.
Dynamic Substitution implements the mechanism described in Terry Ritter's
peer-reviewed paper, "Substitution Cipher with Pseudo-Random Shuffling: The
Dynamic Substitution Combiner," *Cryptologia* 14(4): 289-303 (1990) (full
text at [ciphersbyritter.com/ARTS/DYNSUB2.HTM](http://www.ciphersbyritter.com/ARTS/DYNSUB2.HTM)) —
specifically its core table-and-inverse exchange rule (the paper's own
worked example uses a true random number generator for the exchange index,
which this offline tool replaces with a second, independently-keyed
confusion stream so the same two keywords always reproduce the same
ciphertext). Correctness is checked the same way as MTF/MTB: a hand-worked
vector with both keywords set to `ABC` (`BANANA` -> `BBNACA`), independently
cross-checked against a throwaway script before being locked in as a
permanent KAT in `scripts/test_ciphers.js`, plus a longer round-trip check
with independent, differently-sized keywords to confirm the confusion
keyword's cycling wraps correctly.

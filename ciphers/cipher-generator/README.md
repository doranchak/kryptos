# Cipher Generator

A locally-stored, offline HTML+JS tool for manual encrypt/decrypt and bulk
generation of classical pen-and-paper cipher samples, for practice, testing
solvers, or building training/eval sets.

## Running it

Just open [index.html](index.html) in a browser. No server, no build step,
no network access required at runtime — all corpus text and dictionary data
is embedded directly into the page via `js/data/*.js`.

## Features

- **42 cipher types**: simple substitution, homophonic substitution,
  **Chaocipher** (plus four Chaocipher-like variants: **Single Wheel**,
  **Symmetric Wheels**, **Adjustable Cut Point**, **Double Splice** - see
  below), **Move-to-Front substitution**, **Move-to-Back substitution**,
  **Dynamic Substitution**, autokey, columnar transposition, double columnar
  transposition, rail fence, Myszkowski transposition, ADFGX, ADFGVX, bifid,
  trifid, Quagmire I-IV, **Running Key**, **Running Key ACA**, **Running Key
  I-IV**, **running key + transposition**, **transposition + running key**,
  **Transposition: Periodic**, **Transposition: Inscription+Rotation**,
  Vigenère, Enigma, Beaufort, Porta, Playfair, Hill, scytale, **Solitaire
  (Pontifex)**, **Mirdek**.
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
  - The four Chaocipher variants are not Chaocipher itself - they're
    original mechanical tweaks meant to model what an independent
    cryptographer, who had never heard of Byrne's system, might plausibly
    invent along the way to (or past) the same core idea: a mixed alphabet
    that gets a small local splice - one letter pulled out and reinserted a
    fixed distance away - immediately after every letter, so the
    substitution keeps drifting and never repeats or fractionates. They're
    meant as instructive near-misses for anything trying to recognize
    Chaocipher from that family resemblance alone.
    - **Single Wheel**: the two-disk machine collapsed to one disk, with the
      ciphertext letter read off the point diametrically opposite the
      plaintext letter (13 positions away, its own inverse) instead of off a
      second disk.
    - **Symmetric Wheels**: Chaocipher's exact two-disk lookup, but without
      Byrne's one asymmetry - both disks are permuted by the identical rule
      instead of giving the plaintext disk an extra rotation step.
    - **Adjustable Cut Point**: Chaocipher's exact two-disk lookup and
      rotation rule, but the splice's reinsertion point (always the disk's
      antipodal point, position 13, in Byrne's design) is a chosen key
      parameter from 1-24 instead of a fixed constant - cut position 13 is
      mathematically identical to real Chaocipher, so this variant strictly
      generalizes it.
    - **Double Splice**: Chaocipher's exact two-disk lookup and permutation
      rule, applied twice per letter instead of once - the same "scramble it
      twice for extra security" instinct behind this tool's own Double
      Columnar Transposition, applied to a different cipher family.
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
  - Transposition: Periodic reads the plaintext starting at position 0,
    jumping a fixed `interval` letters at a time (wrapping around with
    mod); when that walk closes back on its own starting point — which
    happens before covering every letter whenever the interval and the
    text length share a common factor — the next walk starts at the
    lowest not-yet-visited position, and so on until every letter's been
    read exactly once. This is the "skip cipher" popularly (if
    imprecisely — see below) described as the way to solve Kryptos K3:
    "count off every 192nd letter."
  - Transposition: Inscription+Rotation is Kryptos K3's actual, exact
    mechanism: the plaintext is written into a grid (column by column),
    that grid is rotated 90°/180°/270° clockwise or counterclockwise, the
    rotated grid's letters (again read column by column) are inscribed
    into a second grid of different dimensions, which is itself rotated —
    reading the final grid off (column by column) produces the
    ciphertext. Grid sizes and rotations are independently configurable
    for both stages; K3 itself uses a 42x8 grid rotated 90° clockwise
    (giving 8x42), inscribed into a 14x24 grid, then rotated 90° clockwise
    again (giving 24x14) — verified letter-for-letter against the real K3
    plaintext and ciphertext (see "Notes on cipher fidelity" below).
- **Manual encrypt/decrypt mode**: pick a cipher, fill in (or randomize) its
  key, type plaintext or ciphertext, run it.
- **Generation mode**: pick a target *ciphertext* length (default 97,
  matching Kryptos K4's own ciphertext length) and a quantity (supports
  generating thousands at once, chunked so the browser tab stays
  responsive), and the tool will, per row:
  1. Estimate how much plaintext the selected cipher needs to produce a
     ciphertext of that length — 1 letter of plaintext per letter of
     ciphertext for the large majority of ciphers, but e.g. half as much for
     ciphers that fractionate/expand text 1-to-2 (Homophonic, ADFGX,
     ADFGVX), or 25 fewer letters for Mirdek (whose ciphertext always opens
     with a fixed 25-letter IV).
  2. Pick a random corpus file, then a random contiguous run of whole words
     from it whose combined letter count (no spaces) exactly matches that
     estimate, rejecting runs that don't look like normal English (long
     repeated-letter runs or unusually low letter-frequency entropy).
  3. Generate a random, cipher-appropriate key — keywords are drawn from the
     top 80% (by frequency rank) of `english_words__practicalcryptography_percentile_99.txt`.
  4. Encrypt, and check the actual ciphertext length against the target.
     Ciphers whose plaintext:ciphertext length ratio is exact and
     content-independent (the majority, plus Homophonic/ADFGX/ADFGVX's exact
     x2 and Mirdek's exact +25) hit the target exactly on the first or
     second try. Ciphers whose padding depends on the actual letters chosen
     (Playfair's double-letter/odd-length fillers, Hill's block-size
     padding) take a few more tries, adjusting the plaintext length from the
     real measured ciphertext length each time. Either way, the ciphertext
     is **never longer than the target** — steps 2-4 repeat with a shorter
     plaintext estimate whenever a try comes out too long, and the row is
     skipped (and counted in the "N skipped" summary) if no plaintext length
     can reach the target at all (e.g. asking Mirdek, whose ciphertext is
     always 25 letters longer than its plaintext, for a ciphertext under 26
     letters) or an even ratio-2 cipher is asked for an odd target length
     (the closest it can get without exceeding is one letter short).
  5. Add the row to a paginated results table; its "CT Len" column reports
     the actual ciphertext length achieved, so any shortfall from the target
     is visible directly rather than needing to be inferred.
  - A **fixed length / length range** toggle switches step 4's success
    condition: fixed mode targets one exact ciphertext length as above;
    range mode accepts any ciphertext length within a min/max window
    (inclusive), which is useful for ciphers that can't land on an
    arbitrary exact length (e.g. an odd target for a ratio-2 cipher, or
    letting Playfair/Hill's content-dependent padding land anywhere in a
    window instead of chasing one exact number).
- **CSV export** with columns: cipher type label, key information,
  ciphertext, plaintext without spaces, plaintext with spaces.
- **Bulk Generate mode**: the same generation engine and fixed-length/range
  toggle as Generation mode above, but run once per registered cipher type
  instead of just the one selected in the dropdown. Give it a quantity (per
  type) and a target length or range, and it generates that many samples of
  **every** cipher type in turn, downloading each type's own CSV
  automatically as soon as that type finishes (so a run can be interrupted
  or a browser download-permission prompt handled without losing the types
  already done), plus a live per-type table of how many were generated vs.
  skipped. A "Download combined CSV" button becomes available once the
  whole run finishes, for a single file with every cipher type's rows
  together instead of one file per type.
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

See `js/generator.js`'s `pickForCiphertextLength` / `LENGTH_MODEL` for the
exact per-cipher plaintext:ciphertext ratios and the retry loop that
verifies (and corrects) against the real `encrypt()` output rather than
trusting the ratio blindly.

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
  (see below), both running-key-plus-transposition ciphers, Transposition:
  Periodic, and Transposition: Inscription+Rotation (hand-worked vectors,
  plus the real Kryptos K3 plaintext/ciphertext for Inscription+Rotation).
  Run with `node scripts/test_ciphers.js`.

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
`scripts/test_ciphers.js` — exact match on both encrypt and decrypt. The
four Chaocipher variants have no external reference (they're original
variations, not historical ciphers), so `scripts/test_ciphers.js`
establishes their correctness by relating each one back to that
already-verified Chaocipher vector instead of an arbitrary locked-in value:
three of the four keep Chaocipher's exact lookup rule and only change how
the disks get permuted *afterward*, so their very first output letter (
computed before either disk has been touched) must equal, and does equal,
real Chaocipher's first output letter on the same starting disks; Adjustable
Cut Point with `cutPosition=13` is mathematically identical to real
Chaocipher end to end and reproduces its full reference ciphertext exactly;
Double Splice is independently cross-checked by hand-driving the exported
`chaoStep` primitive twice per letter rather than by calling its own
`encrypt()` and comparing the result to itself. (An earlier "Cross-Coupled
Wheels" variant design — routing each disk's extracted letter into the
*other* disk's splice point — was dropped after round-trip testing caught a
real bug in it: since both disks are independent permutations of the same
26 letters, moving a letter's value from one disk directly into the other
creates a duplicate there and silently drops a different letter, corrupting
the disk after enough letters. Double Splice replaced it precisely because
it can't have that class of bug — it only ever rearranges each disk using
its own existing letters.)
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

Transposition: Inscription+Rotation was reverse-engineered directly from the
real Kryptos K3 plaintext/ciphertext: a brute-force search over grid fill/read
order (row- vs. column-major), rotation direction, and grid dimensions found
that filling and reading every grid column-major, with a 42x8 grid rotated
90° clockwise, inscribed into a 14x24 grid, then rotated 90° clockwise again,
reproduces the real 336-letter K3 ciphertext from the real K3 plaintext
exactly — and decrypts it back exactly — which is now a permanent KAT in
`scripts/test_ciphers.js`. Transposition: Periodic (the "skip cipher" widely
described online as "count off every 192nd letter" to solve K3) is a real,
independently useful interval-transposition technique in its own right, and
is checked with hand-worked vectors, but it is *not* a literal
reconstruction of K3: an exhaustive search (every interval 1-335 combined
with every starting offset 0-335, plus the equivalent "counting-out"/
Josephus formulation) found no parameterization of it that reproduces the
real K3 ciphertext letter-for-letter. The "192nd letter" description appears
to be a widely-repeated approximate/folk description of the
Inscription+Rotation mechanism above (336 = 42x8 = 14x24, and 4x48 = 192
connects to those same grid dimensions) rather than an independently exact
algorithm.

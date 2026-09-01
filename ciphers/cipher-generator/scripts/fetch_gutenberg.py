#!/usr/bin/env python3
"""Download a curated list of public-domain ebooks from Project Gutenberg,
strip the Gutenberg boilerplate header/footer, normalize to A-Z-only text,
and split each book into multiple corpus files (chunks of ~WORDS_PER_CHUNK
words) so the generator has many independent, book-length sources of text."""
import os
import re
import sys
import time
import urllib.request

OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "corpora")
UA = "KryptosCipherGeneratorTool/1.0 (educational research tool; contact: doranchak@gmail.com)"
WORDS_PER_CHUNK = 2500
MIN_CHUNKS_PER_BOOK = 2
MAX_CHUNKS_PER_BOOK = 6

# (gutenberg id, short slug, title) - a mix of classic public-domain prose
BOOKS = [
    (11, "alice_wonderland", "Alice's Adventures in Wonderland"),
    (1342, "pride_prejudice", "Pride and Prejudice"),
    (84, "frankenstein", "Frankenstein"),
    (2701, "moby_dick", "Moby Dick"),
    (1661, "sherlock_holmes", "The Adventures of Sherlock Holmes"),
    (98, "tale_two_cities", "A Tale of Two Cities"),
    (345, "dracula", "Dracula"),
    (76, "huckleberry_finn", "Adventures of Huckleberry Finn"),
    (1952, "yellow_wallpaper", "The Yellow Wallpaper"),
    (43, "jekyll_hyde", "Dr Jekyll and Mr Hyde"),
    (16328, "beowulf", "Beowulf"),
    (174, "dorian_gray", "The Picture of Dorian Gray"),
    (5200, "metamorphosis", "Metamorphosis"),
    (2554, "crime_punishment", "Crime and Punishment"),
    (36, "war_of_worlds", "The War of the Worlds"),
    (203, "arabian_nights", "Arabian Nights"),
    (215, "call_of_wild", "The Call of the Wild"),
    (1080, "modest_proposal", "A Modest Proposal"),
    (30254, "romance_three_kingdoms1", "Romance of the Three Kingdoms Vol 1"),
    (135, "les_miserables", "Les Miserables"),
    (2600, "war_and_peace", "War and Peace"),
    (55, "wizard_of_oz", "The Wonderful Wizard of Oz"),
    (120, "treasure_island", "Treasure Island"),
    (74, "tom_sawyer", "The Adventures of Tom Sawyer"),
    (161, "sense_sensibility", "Sense and Sensibility"),
    (46, "christmas_carol", "A Christmas Carol"),
    (1400, "great_expectations", "Great Expectations"),
    (2591, "grimms_tales", "Grimms' Fairy Tales"),
    (768, "wuthering_heights", "Wuthering Heights"),
    (1232, "the_prince", "The Prince"),
    (844, "importance_of_being_earnest", "The Importance of Being Earnest"),
    (2542, "doll_house", "A Doll's House"),
    (25344, "scarlet_letter", "The Scarlet Letter"),
    (829, "gullivers_travels", "Gulliver's Travels"),
    (394, "cranford", "Cranford"),
    (6130, "iliad", "The Iliad"),
    (1727, "odyssey", "The Odyssey"),
    (16, "peter_pan", "Peter Pan"),
    (521, "life_on_mississippi", "Life on the Mississippi"),
]

URL_TMPLS = [
    "https://www.gutenberg.org/cache/epub/{id}/pg{id}.txt",
    "https://www.gutenberg.org/files/{id}/{id}-0.txt",
    "https://www.gutenberg.org/files/{id}/{id}.txt",
]

START_RE = re.compile(r"\*\*\*\s*START OF (THE|THIS) PROJECT GUTENBERG EBOOK.*?\*\*\*", re.IGNORECASE | re.DOTALL)
END_RE = re.compile(r"\*\*\*\s*END OF (THE|THIS) PROJECT GUTENBERG EBOOK", re.IGNORECASE)


def download(book_id):
    for tmpl in URL_TMPLS:
        url = tmpl.format(id=book_id)
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read()
                for enc in ("utf-8", "latin-1"):
                    try:
                        return raw.decode(enc)
                    except UnicodeDecodeError:
                        continue
        except Exception as e:
            sys.stderr.write(f"  ({url} failed: {e})\n")
            continue
    return None


def strip_boilerplate(text):
    m = START_RE.search(text)
    if m:
        text = text[m.end():]
    m = END_RE.search(text)
    if m:
        text = text[:m.start()]
    return text


def normalize(text):
    text = text.upper()
    text = re.sub(r"[^A-Z]+", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    total_chunks = 0
    for book_id, slug, title in BOOKS:
        # skip if already fetched (any chunk file present)
        existing = [f for f in os.listdir(OUT_DIR) if f.startswith(f"gutenberg_{book_id}_{slug}_")]
        if existing:
            print(f"skip {title} (already have {len(existing)} chunks)")
            total_chunks += len(existing)
            continue
        print(f"fetching {title} (id {book_id})...")
        raw = download(book_id)
        if raw is None:
            print(f"  FAILED to download {title}")
            continue
        body = strip_boilerplate(raw)
        norm = normalize(body)
        words = norm.split(" ")
        total_words = len(words)

        if total_words <= WORDS_PER_CHUNK:
            starts = [0]
        else:
            # scale chunk count with book length, but cap so a handful of very
            # long novels (War and Peace, Les Miserables, ...) don't dominate
            # the corpus; sample chunks evenly spread across the whole book.
            n_chunks = max(MIN_CHUNKS_PER_BOOK, min(MAX_CHUNKS_PER_BOOK, round(total_words / 30000)))
            usable = total_words - WORDS_PER_CHUNK
            step = usable / max(1, n_chunks - 1) if n_chunks > 1 else 0
            starts = [int(round(i * step)) for i in range(n_chunks)]

        n_chunks = 0
        for i, start in enumerate(starts):
            chunk_words = words[start:start + WORDS_PER_CHUNK]
            if not chunk_words:
                continue
            chunk_text = " ".join(chunk_words)
            fname = f"gutenberg_{book_id}_{slug}_{i + 1:02d}.txt"
            with open(os.path.join(OUT_DIR, fname), "w") as f:
                f.write(chunk_text + "\n")
            total_chunks += 1
            n_chunks += 1
        print(f"  -> {n_chunks} chunks, {total_words} words in source")
        time.sleep(0.5)

    print(f"Done. Total chunk files (including pre-existing): {total_chunks}")


if __name__ == "__main__":
    main()

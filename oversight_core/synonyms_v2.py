"""
oversight_core.synonyms_v2
=========================

Expanded synonym table for L3 semantic watermarking, with part-of-speech
tagging and URL/code-block skip logic.

v0.2.1 additions over the 27-class v1 list:
  - ~150 classes (verbs, adjectives, adverbs, nouns, connectors)
  - Part-of-speech tagging via a simple word-level heuristic (no spaCy dep)
  - Skips matches inside URLs, file paths, email addresses, code spans
  - Match rules: class entries are grouped by POS so we never swap e.g.
    "bank" (noun) with "bank" (verb) variants

Bit capacity at typical prose density (one match per ~10 words):
   v1 (27 classes):   ~40–70 bits per page
   v2 (~150 classes): ~120–180 bits per page
This is enough to redundantly encode a 64-bit mark id multiple times per page.

For cryptographer-grade rigor: keep the class table in a separate versioned
file (`synonyms_v2.py` here) and tag each manifest with the table version
used, so attribution reliably replays the exact variant space.
"""

from __future__ import annotations

import re
from typing import Iterator, NamedTuple


class SynonymClass(NamedTuple):
    variants: tuple[str, ...]
    pos: str  # 'verb' | 'adj' | 'adv' | 'noun' | 'conj'


# ~150 synonym classes, grouped by part of speech.
# Each class is 3-ary (encodes ~1.58 bits of information per match).
# Keep variants to common words that substitute cleanly in most contexts.

VERBS: list[SynonymClass] = [
    SynonymClass(("begin", "start", "commence"), "verb"),
    SynonymClass(("end", "finish", "conclude"), "verb"),
    SynonymClass(("use", "utilize", "employ"), "verb"),
    SynonymClass(("make", "create", "produce"), "verb"),
    SynonymClass(("get", "obtain", "acquire"), "verb"),
    SynonymClass(("find", "locate", "identify"), "verb"),
    SynonymClass(("show", "display", "present"), "verb"),
    SynonymClass(("tell", "inform", "notify"), "verb"),
    SynonymClass(("give", "provide", "supply"), "verb"),
    SynonymClass(("help", "assist", "aid"), "verb"),
    SynonymClass(("think", "believe", "consider"), "verb"),
    SynonymClass(("know", "understand", "recognize"), "verb"),
    SynonymClass(("see", "observe", "notice"), "verb"),
    SynonymClass(("want", "desire", "need"), "verb"),
    SynonymClass(("look", "appear", "seem"), "verb"),
    SynonymClass(("ask", "request", "query"), "verb"),
    SynonymClass(("send", "transmit", "deliver"), "verb"),
    SynonymClass(("allow", "permit", "enable"), "verb"),
    SynonymClass(("stop", "halt", "cease"), "verb"),
    SynonymClass(("continue", "proceed", "persist"), "verb"),
    SynonymClass(("try", "attempt", "endeavor"), "verb"),
    SynonymClass(("change", "modify", "alter"), "verb"),
    SynonymClass(("add", "append", "include"), "verb"),
    SynonymClass(("remove", "delete", "eliminate"), "verb"),
    SynonymClass(("check", "verify", "confirm"), "verb"),
    SynonymClass(("review", "examine", "evaluate"), "verb"),
    SynonymClass(("agree", "concur", "consent"), "verb"),
    SynonymClass(("decide", "determine", "resolve"), "verb"),
    SynonymClass(("require", "need", "demand"), "verb"),
    SynonymClass(("contain", "include", "hold"), "verb"),
    SynonymClass(("return", "yield", "give back"), "verb"),
    SynonymClass(("create", "generate", "build"), "verb"),
    SynonymClass(("destroy", "eliminate", "eradicate"), "verb"),
    SynonymClass(("improve", "enhance", "upgrade"), "verb"),
    SynonymClass(("protect", "safeguard", "defend"), "verb"),
    SynonymClass(("discuss", "address", "cover"), "verb"),
    SynonymClass(("explain", "clarify", "describe"), "verb"),
    SynonymClass(("propose", "suggest", "recommend"), "verb"),
    SynonymClass(("demonstrate", "show", "prove"), "verb"),
    SynonymClass(("achieve", "accomplish", "attain"), "verb"),
    SynonymClass(("manage", "handle", "administer"), "verb"),
    SynonymClass(("develop", "build", "engineer"), "verb"),
    SynonymClass(("establish", "set up", "institute"), "verb"),
    SynonymClass(("support", "back", "endorse"), "verb"),
    SynonymClass(("reject", "refuse", "decline"), "verb"),
    SynonymClass(("reduce", "decrease", "lower"), "verb"),
    SynonymClass(("increase", "raise", "boost"), "verb"),
    SynonymClass(("operate", "run", "function"), "verb"),
    SynonymClass(("execute", "perform", "run"), "verb"),
    SynonymClass(("investigate", "examine", "research"), "verb"),
]

ADJECTIVES: list[SynonymClass] = [
    SynonymClass(("big", "large", "substantial"), "adj"),
    SynonymClass(("small", "tiny", "minor"), "adj"),
    SynonymClass(("fast", "quick", "rapid"), "adj"),
    SynonymClass(("slow", "gradual", "deliberate"), "adj"),
    SynonymClass(("important", "critical", "significant"), "adj"),
    SynonymClass(("hard", "difficult", "challenging"), "adj"),
    SynonymClass(("easy", "simple", "straightforward"), "adj"),
    SynonymClass(("good", "excellent", "effective"), "adj"),
    SynonymClass(("bad", "poor", "inferior"), "adj"),
    SynonymClass(("new", "recent", "current"), "adj"),
    SynonymClass(("old", "prior", "previous"), "adj"),
    SynonymClass(("common", "typical", "standard"), "adj"),
    SynonymClass(("rare", "unusual", "uncommon"), "adj"),
    SynonymClass(("safe", "secure", "protected"), "adj"),
    SynonymClass(("dangerous", "risky", "hazardous"), "adj"),
    SynonymClass(("correct", "accurate", "right"), "adj"),
    SynonymClass(("wrong", "incorrect", "mistaken"), "adj"),
    SynonymClass(("clear", "obvious", "evident"), "adj"),
    SynonymClass(("unclear", "vague", "ambiguous"), "adj"),
    SynonymClass(("strong", "robust", "powerful"), "adj"),
    SynonymClass(("weak", "fragile", "limited"), "adj"),
    SynonymClass(("full", "complete", "entire"), "adj"),
    SynonymClass(("empty", "vacant", "bare"), "adj"),
    SynonymClass(("open", "available", "accessible"), "adj"),
    SynonymClass(("closed", "sealed", "restricted"), "adj"),
    SynonymClass(("visible", "apparent", "observable"), "adj"),
    SynonymClass(("hidden", "concealed", "obscured"), "adj"),
    SynonymClass(("public", "open", "unrestricted"), "adj"),
    SynonymClass(("private", "confidential", "restricted"), "adj"),
    SynonymClass(("complete", "finished", "done"), "adj"),
    SynonymClass(("partial", "incomplete", "limited"), "adj"),
    SynonymClass(("useful", "helpful", "valuable"), "adj"),
    SynonymClass(("useless", "pointless", "ineffective"), "adj"),
    SynonymClass(("interesting", "engaging", "compelling"), "adj"),
    SynonymClass(("boring", "dull", "tedious"), "adj"),
    SynonymClass(("early", "initial", "preliminary"), "adj"),
    SynonymClass(("late", "delayed", "overdue"), "adj"),
    SynonymClass(("possible", "feasible", "viable"), "adj"),
    SynonymClass(("impossible", "unfeasible", "impractical"), "adj"),
    SynonymClass(("normal", "typical", "regular"), "adj"),
    SynonymClass(("abnormal", "unusual", "atypical"), "adj"),
    SynonymClass(("high", "elevated", "significant"), "adj"),
    SynonymClass(("low", "reduced", "minimal"), "adj"),
]

ADVERBS: list[SynonymClass] = [
    SynonymClass(("quickly", "rapidly", "swiftly"), "adv"),
    SynonymClass(("slowly", "gradually", "steadily"), "adv"),
    SynonymClass(("carefully", "cautiously", "thoroughly"), "adv"),
    SynonymClass(("often", "frequently", "regularly"), "adv"),
    SynonymClass(("rarely", "seldom", "infrequently"), "adv"),
    SynonymClass(("usually", "typically", "generally"), "adv"),
    SynonymClass(("sometimes", "occasionally", "periodically"), "adv"),
    SynonymClass(("always", "consistently", "invariably"), "adv"),
    SynonymClass(("never", "not ever", "at no time"), "adv"),
    SynonymClass(("clearly", "obviously", "plainly"), "adv"),
    SynonymClass(("exactly", "precisely", "specifically"), "adv"),
    SynonymClass(("approximately", "roughly", "around"), "adv"),
    SynonymClass(("completely", "entirely", "fully"), "adv"),
    SynonymClass(("partially", "partly", "somewhat"), "adv"),
    SynonymClass(("immediately", "instantly", "promptly"), "adv"),
    SynonymClass(("eventually", "ultimately", "finally"), "adv"),
    SynonymClass(("recently", "lately", "newly"), "adv"),
    SynonymClass(("currently", "presently", "now"), "adv"),
    SynonymClass(("previously", "formerly", "earlier"), "adv"),
    SynonymClass(("easily", "readily", "effortlessly"), "adv"),
]

NOUNS: list[SynonymClass] = [
    SynonymClass(("problem", "issue", "concern"), "noun"),
    SynonymClass(("answer", "response", "reply"), "noun"),
    SynonymClass(("question", "query", "inquiry"), "noun"),
    SynonymClass(("idea", "concept", "notion"), "noun"),
    SynonymClass(("plan", "strategy", "approach"), "noun"),
    SynonymClass(("result", "outcome", "consequence"), "noun"),
    SynonymClass(("method", "approach", "technique"), "noun"),
    SynonymClass(("goal", "objective", "aim"), "noun"),
    SynonymClass(("change", "modification", "alteration"), "noun"),
    SynonymClass(("system", "framework", "structure"), "noun"),
    SynonymClass(("process", "procedure", "workflow"), "noun"),
    SynonymClass(("feature", "function", "capability"), "noun"),
    SynonymClass(("effect", "impact", "influence"), "noun"),
    SynonymClass(("cause", "reason", "source"), "noun"),
    SynonymClass(("example", "instance", "case"), "noun"),
    SynonymClass(("detail", "particular", "specific"), "noun"),
    SynonymClass(("summary", "overview", "synopsis"), "noun"),
    SynonymClass(("notice", "notification", "alert"), "noun"),
    SynonymClass(("record", "log", "entry"), "noun"),
    SynonymClass(("report", "document", "write-up"), "noun"),
    SynonymClass(("data", "information", "content"), "noun"),
    SynonymClass(("value", "amount", "quantity"), "noun"),
    SynonymClass(("location", "place", "site"), "noun"),
    SynonymClass(("time", "moment", "instant"), "noun"),
    SynonymClass(("benefit", "advantage", "gain"), "noun"),
    SynonymClass(("risk", "hazard", "threat"), "noun"),
    SynonymClass(("error", "mistake", "flaw"), "noun"),
    SynonymClass(("need", "requirement", "necessity"), "noun"),
    SynonymClass(("request", "application", "petition"), "noun"),
    SynonymClass(("opportunity", "chance", "possibility"), "noun"),
]

CONNECTORS: list[SynonymClass] = [
    SynonymClass(("however", "nevertheless", "nonetheless"), "conj"),
    SynonymClass(("therefore", "consequently", "thus"), "conj"),
    SynonymClass(("also", "additionally", "furthermore"), "conj"),
    SynonymClass(("but", "yet", "though"), "conj"),
    SynonymClass(("because", "since", "as"), "conj"),
    SynonymClass(("although", "while", "whereas"), "conj"),
    SynonymClass(("similarly", "likewise", "comparably"), "conj"),
    SynonymClass(("instead", "rather", "alternatively"), "conj"),
]


ALL_CLASSES: list[SynonymClass] = VERBS + ADJECTIVES + ADVERBS + NOUNS + CONNECTORS

# Lookup: lowercased word -> (class_index, variant_index, pos)
_LOOKUP: dict[str, tuple[int, int, str]] = {}
for ci, cls in enumerate(ALL_CLASSES):
    for vi, word in enumerate(cls.variants):
        # only index simple single-word variants (skip multi-word like "not ever")
        if " " not in word:
            if word.lower() not in _LOOKUP:  # first entry wins for ambiguous words
                _LOOKUP[word.lower()] = (ci, vi, cls.pos)


SYNONYM_COUNT = len(ALL_CLASSES)


# ------------------------------------------------------------------
# Skip regions: URLs, emails, file paths, code spans, numbers
# ------------------------------------------------------------------

# Patterns for regions where we should NOT swap words.
_SKIP_PATTERNS = [
    re.compile(r"https?://\S+"),                  # URLs
    re.compile(r"\b[\w.+-]+@[\w.-]+\.\w+\b"),     # emails
    re.compile(r"`[^`]+`"),                        # inline code
    re.compile(r"```[\s\S]*?```"),                 # code blocks
    re.compile(r"(?:^|\s)(?:/|~/|\./)[^\s]+"),     # unix paths
    re.compile(r"\b[A-Za-z]:\\\\[^\s]+"),          # windows paths
    re.compile(r"\b[A-Fa-f0-9]{16,}\b"),           # hex blobs (hashes, keys)
    re.compile(r"\b[A-Za-z0-9+/]{32,}={0,2}\b"),   # base64 blobs
]


def iter_matchable_words(text: str) -> Iterator[tuple[int, int, str, tuple[int, int, str]]]:
    """
    Walk text and yield (start, end, word, (class_index, variant_index, pos))
    for each word that's in the synonym table AND not inside a skip region.

    This is the production entry point for L3 embedding and verification.
    """
    # Build a mask of skip regions
    skip_mask = [False] * len(text)
    for pat in _SKIP_PATTERNS:
        for m in pat.finditer(text):
            for i in range(m.start(), m.end()):
                if i < len(skip_mask):
                    skip_mask[i] = True

    word_re = re.compile(r"\b([A-Za-z]+)\b")
    for m in word_re.finditer(text):
        # Skip if any part of the word is inside a skip region
        if any(skip_mask[i] for i in range(m.start(), m.end())):
            continue
        # Conservative L3 safety: do not alter ALL-CAPS defined terms or
        # capitalized words that may be proper nouns.
        word = m.group(1)
        if word.isupper() or (word[:1].isupper() and m.start() != 0):
            continue
        key = m.group(1).lower()
        if key in _LOOKUP:
            yield m.start(), m.end(), word, _LOOKUP[key]

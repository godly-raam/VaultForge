"""Access to the bundled passphrase word list.

The word list is data, not code, so it lives next to the package and is read
through :mod:`importlib.resources`. That works both from a source checkout and
from an installed wheel without hard-coding filesystem paths.
"""

from __future__ import annotations

from functools import lru_cache
from importlib import resources

_WORDLIST_RESOURCE = "data/wordlist.txt"


class WordListError(RuntimeError):
    """Raised when the bundled word list is missing or malformed."""


@lru_cache(maxsize=1)
def load_wordlist() -> tuple[str, ...]:
    """Load, validate, and cache the bundled word list.

    Validation is cheap and guards against packaging mistakes (for example, a
    word list that was accidentally truncated or duplicated). Any violation is
    a build error, so it is surfaced as an exception rather than silently
    reducing passphrase entropy.
    """
    text = resources.files("vaultforge").joinpath(_WORDLIST_RESOURCE).read_text(encoding="utf-8")
    words = tuple(line.strip() for line in text.splitlines() if line.strip())

    if len(words) < 1296:
        raise WordListError(
            f"bundled word list is too small ({len(words)} words); expected >= 1296"
        )
    if len(set(words)) != len(words):
        raise WordListError("bundled word list contains duplicate entries")
    if not all(word.isalpha() and word.islower() for word in words):
        raise WordListError("bundled word list must contain lowercase alphabetic words")

    return words

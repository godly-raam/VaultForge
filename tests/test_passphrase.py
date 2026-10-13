"""Tests for passphrase generation and the bundled word list."""

import pytest

from vaultforge import generators
from vaultforge.wordlist import load_wordlist


def test_wordlist_is_present_and_well_formed():
    words = load_wordlist()
    assert len(words) == 7772
    assert len(set(words)) == len(words)
    assert all(word.isalpha() and word.islower() for word in words)


def test_wordlist_is_cached():
    assert load_wordlist() is load_wordlist()


@pytest.mark.parametrize("word_count", [1, 3, 6, 12])
def test_passphrase_has_requested_word_count(word_count):
    phrase = generators.generate_passphrase(word_count)
    assert len(phrase.split("-")) == word_count


def test_passphrase_custom_separator():
    phrase = generators.generate_passphrase(4, separator=" ")
    assert len(phrase.split(" ")) == 4


def test_passphrase_words_come_from_wordlist():
    vocab = set(load_wordlist())
    for _ in range(50):
        phrase = generators.generate_passphrase(6)
        assert all(word in vocab for word in phrase.split("-"))


def test_passphrase_capitalize_option():
    phrase = generators.generate_passphrase(5, capitalize=True)
    for word in phrase.split("-"):
        assert word[0].isupper()


def test_passphrase_rejects_non_positive_word_count():
    with pytest.raises(ValueError):
        generators.generate_passphrase(0)

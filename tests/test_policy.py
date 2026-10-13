"""Tests for password policy construction and validation."""

import pytest

from vaultforge.policy import PasswordPolicy, PolicyError


def test_default_policy_is_valid():
    PasswordPolicy(length=16).validate()


def test_enabled_classes_default_includes_all_four():
    policy = PasswordPolicy(length=16)
    assert policy.enabled_classes() == ("lowercase", "uppercase", "digits", "symbols")
    assert policy.required_classes == 4


def test_disabling_classes_updates_enabled_list():
    policy = PasswordPolicy(length=16, symbols=False, uppercase=False)
    assert policy.enabled_classes() == ("lowercase", "digits")


@pytest.mark.parametrize("length", [0, -1, -100])
def test_non_positive_length_is_rejected(length):
    with pytest.raises(PolicyError, match="length must be >= 1"):
        PasswordPolicy(length=length).validate()


def test_no_enabled_classes_is_rejected():
    policy = PasswordPolicy(
        length=10, lowercase=False, uppercase=False, digits=False, symbols=False
    )
    with pytest.raises(PolicyError, match="at least one character class"):
        policy.validate()


@pytest.mark.parametrize("length", [1, 2, 3])
def test_length_shorter_than_class_count_is_impossible(length):
    # Four classes are enabled by default, so a length of 1-3 cannot contain
    # at least one character from each.
    with pytest.raises(PolicyError, match="too short"):
        PasswordPolicy(length=length).validate()


def test_length_equal_to_class_count_is_allowed():
    PasswordPolicy(length=4).validate()


def test_single_class_allows_single_character():
    PasswordPolicy(length=1, uppercase=False, digits=False, symbols=False).validate()

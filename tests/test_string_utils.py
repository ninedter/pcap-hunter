"""Tests for string utility functions."""

from __future__ import annotations

from app.utils.string_utils import make_slug, uniq_sorted


class TestUniqSorted:
    def test_basic(self):
        assert uniq_sorted([3, 1, 2, 1]) == [1, 2, 3]

    def test_with_empty_strings(self):
        assert uniq_sorted(["b", "", "a", ""]) == ["a", "b"]

    def test_none_input(self):
        assert uniq_sorted(None) == []

    def test_empty_list(self):
        assert uniq_sorted([]) == []

    def test_with_none_values(self):
        assert uniq_sorted(["a", None, "b", None]) == ["a", "b"]

    def test_single_element(self):
        assert uniq_sorted(["x"]) == ["x"]

    def test_all_duplicates(self):
        assert uniq_sorted([1, 1, 1]) == [1]


class TestMakeSlug:
    def test_basic(self):
        assert make_slug("Hello World") == "hello_world"

    def test_special_characters(self):
        assert make_slug("Test: Phase (1)") == "test__phase__1_"

    def test_empty_string(self):
        assert make_slug("") == ""

    def test_already_slug(self):
        assert make_slug("hello_world") == "hello_world"

    def test_numbers(self):
        assert make_slug("Stage 1") == "stage_1"

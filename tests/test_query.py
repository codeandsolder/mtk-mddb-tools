"""Tests for raw search rendering."""

from mtk_mddb.query import render, search_blob


def test_search_blob_allows_overlaps() -> None:
    assert list(search_blob(b"aaaa", b"aa")) == [0, 1, 2]


def test_render_binary_context() -> None:
    assert render(b"A\0\n\t\xffZ", 0, 6) == r"A\0\n\t\xffZ"

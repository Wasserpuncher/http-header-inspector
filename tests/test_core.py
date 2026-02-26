from http_header_inspector.core import normalize_url


def test_normalize_url_adds_scheme():
    assert normalize_url("example.com").startswith("https://")


def test_normalize_url_keeps_scheme():
    assert normalize_url("http://example.com").startswith("http://")

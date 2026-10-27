"""Check embedded translation coverage without changing relay wire/export formats."""
from html.parser import HTMLParser
import json
import re

from src.statistics_ui import PAGE
from src.web_localization import TRANSLATIONS, localize_page


class Markers(HTMLParser):
    def __init__(self):
        super().__init__()
        self.labels = []

    def handle_starttag(self, tag, attrs):
        for name, value in attrs:
            if name in ("data-i18n", "data-i18n-aria", "data-i18n-alt"):
                self.labels.append(value)


def test_dashboard_static_and_dynamic_labels_have_russian_translations():
    parser = Markers()
    parser.feed(PAGE)
    assert len(parser.labels) >= 15
    for label in parser.labels:
        assert label in TRANSLATIONS, label
        assert re.search("[А-Яа-яЁё]", TRANSLATIONS[label]), label
    for label in re.findall(r"\bt\('([^']+)'\)", PAGE):
        assert label in TRANSLATIONS, label
    assert 'id="carriex-language"' in PAGE
    assert "new Intl.NumberFormat(i18n.language" in PAGE
    assert "carriex-language-change',refresh" in PAGE


def test_embedded_dictionary_is_valid_and_cannot_close_its_script():
    page = localize_page('<html><style></style><p>Public content</p></html>')
    encoded = re.search(r"const translations=(\{.*?\}),selector=", page).group(1)
    assert json.loads(encoded) == TRANSLATIONS
    assert "<" not in encoded
    assert page.count("<script>") == 1
    assert "['en','ru'].includes(query)" in page

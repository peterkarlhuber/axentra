from __future__ import annotations

import pytest

from axentra.core.errors import ValidationFailed
from axentra.notify.render import check_variables, placeholders, render, render_variant, resolve_locale

VARIANTS = {
    "en": {"subject": "Hi {{ name }}", "text": "Hello {{name}}", "html": "<p>{{ name }}</p>"},
    "de": {"subject": "Hallo {{ name }}", "text": "Hallo {{ name }}", "html": None},
}


def test_html_bodies_escape_values_text_does_not():
    v = {"name": '<script>alert("x")</script>&\'"'}
    assert render("<p>{{ name }}</p>", v, "html") == (
        "<p>&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;&amp;&#x27;&quot;</p>"
    )
    assert render("{{ name }}", v, "text") == v["name"]


def test_no_code_execution_and_single_pass():
    # Values that look like placeholders are not expanded again.
    assert render("{{ a }}", {"a": "{{ b }}", "b": "secret"}, "text") == "{{ b }}"
    for bad in ("{{ a.__class__ }}", "{{ a | upper }}", "{% for x in y %}", "{{ 1+1 }}", "{{ a"):
        with pytest.raises(ValidationFailed):
            placeholders(bad if bad.startswith("{{") else "{{" + bad)


def test_missing_variables_are_validation_errors():
    with pytest.raises(ValidationFailed) as exc:
        render("{{ a }} {{ b }}", {"a": "x", "b": None}, "text")
    assert exc.value.extra["missing"] == ["b"]


def test_subject_has_no_line_breaks():
    assert (
        render("Hi {{ n }}", {"n": "a\r\nBcc: evil@example.com"}, "subject") == "Hi a Bcc: evil@example.com"
    )


def test_locale_fallback_chain():
    assert resolve_locale("de-AT", VARIANTS) == "de"
    assert resolve_locale("de_at", VARIANTS) == "de"
    assert resolve_locale("fr", VARIANTS) == "en"
    assert resolve_locale(None, VARIANTS) == "en"
    with pytest.raises(ValidationFailed):
        resolve_locale("fr", {"de": {}})
    r = render_variant(VARIANTS, "de-CH", {"name": "Eva"})
    assert (r.locale, r.subject, r.html) == ("de", "Hallo Eva", None)


def test_variable_checks():
    with pytest.raises(ValidationFailed):
        check_variables({"bad-name": "x"})
    with pytest.raises(ValidationFailed):
        check_variables({"a": "x" * 10_001})
    with pytest.raises(ValidationFailed):
        render("{{ a }}", {"a": {"nested": 1}}, "text")
    assert render("{{ a }}/{{ b }}", {"a": 3, "b": True}, "text") == "3/true"

"""AQL comparison operators, and the silent-degradation bug they replaced.

`category = "Messages"` used to tokenise as three unrelated free-text terms —
`category`, `=`, `Messages` — ANDed together, which matched nothing. The query
did not error. It returned zero results, and an examiner reading that would
conclude the device held no messages.

That is the worst class of bug this tool can have: not a crash, but a confident
wrong answer. These tests exist so the grammar cannot regress to it.
"""
from __future__ import annotations

import unittest

from argus.analyze.search import compile_query
from argus.core.errors import QueryError


class EqualsSyntax(unittest.TestCase):
    def test_equals_compiles_to_a_field_comparison(self) -> None:
        compiled = compile_query('category = "Messages"')
        self.assertEqual(compiled.where, "category = ?")
        self.assertEqual(compiled.params, ["Messages"])

    def test_equals_does_not_degrade_to_free_text(self) -> None:
        """The specific failure mode: three LIKE terms and no error."""
        compiled = compile_query('category = "Messages"')
        self.assertNotIn("LIKE", compiled.where)
        self.assertNotIn("%category%", compiled.params)

    def test_colon_and_equals_agree(self) -> None:
        for colon, equals in [('category:Messages', 'category = "Messages"'),
                              ('app:WhatsApp', 'app = WhatsApp'),
                              ('deleted:true', 'deleted = true')]:
            a, b = compile_query(colon), compile_query(equals)
            self.assertEqual(a.where, b.where, colon)
            self.assertEqual(a.params, b.params, colon)

    def test_spacing_is_not_significant(self) -> None:
        for text in ('category="Messages"', 'category ="Messages"',
                     'category= "Messages"', 'category  =  "Messages"'):
            self.assertEqual(compile_query(text).where, "category = ?", text)

    def test_boolean_combination(self) -> None:
        compiled = compile_query('category = "Messages" AND deleted = true')
        self.assertIn("category = ?", compiled.where)
        self.assertIn("recovery <> ?", compiled.where)
        self.assertEqual(compiled.params, ["Messages", "allocated"])


class ComparisonOperators(unittest.TestCase):
    def test_strict_greater_than_is_not_widened(self) -> None:
        """`> 0.8` must not become `>= 0.8`.

        Including records at exactly the threshold inflates a count that ends up
        quoted in a report.
        """
        compiled = compile_query("confidence > 0.8")
        self.assertEqual(compiled.where, "confidence > ?")
        self.assertEqual(compiled.params, [0.8])

    def test_each_operator_maps_to_itself(self) -> None:
        for op in (">", ">=", "<", "<="):
            compiled = compile_query(f"confidence {op} 0.5")
            self.assertEqual(compiled.where, f"confidence {op} ?", op)

    def test_legacy_embedded_operator_still_works(self) -> None:
        self.assertEqual(compile_query("confidence:>0.8").where,
                         "confidence > ?")

    def test_timestamp_comparison(self) -> None:
        compiled = compile_query("timestamp > 2024-01-01")
        self.assertEqual(compiled.where, "timestamp > ?")
        self.assertEqual(len(compiled.params), 1)
        self.assertIsInstance(compiled.params[0], int)


class RefusesRatherThanGuesses(unittest.TestCase):
    """A query that cannot mean what it says must fail loudly."""

    def test_comparison_on_an_unordered_field_is_refused(self) -> None:
        for text in ("app > 3", "category < Messages", "body >= x"):
            with self.assertRaises(QueryError, msg=text):
                compile_query(text)

    def test_the_refusal_names_the_valid_fields(self) -> None:
        try:
            compile_query("app > 3")
        except QueryError as exc:
            self.assertIn("confidence", str(exc))
        else:
            self.fail("expected a QueryError")

    def test_non_numeric_confidence_is_refused(self) -> None:
        with self.assertRaises(QueryError):
            compile_query("confidence > high")

    def test_genuine_free_text_still_works(self) -> None:
        """Not everything with no operator is a mistake."""
        compiled = compile_query("burner phone")
        self.assertIn("LIKE", compiled.where)

    def test_empty_query_matches_everything(self) -> None:
        self.assertEqual(compile_query("").where, "1=1")


if __name__ == "__main__":
    unittest.main()

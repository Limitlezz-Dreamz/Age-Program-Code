# Golden detection notes (M2)

Golden tests run only when fixtures are present under `tests/fixtures/ext/`
(fetched via `just fixtures` / `LW_FIXTURES=1`).

If a listed fixture is missing or does not contain the expected event, note it
here rather than weakening the built-in rule.

<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-08-30 | Updated: 2026-08-30 -->

# transforms

## Purpose
Payload mutations applied across the whole corpus, so every probe can be tested in
its raw form and in obfuscated/encoded forms. Comparing success rates across
transforms is what locates a defect in the input filter versus the model itself
(e.g. `unicode.zero_width` raising the bypass rate points at input normalization).

## Key Files
| File | Description |
|------|-------------|
| `__init__.py` | The whole subpackage: the `Transform` base, every built-in transform, and `build_transform`/`select_transforms` |

Built-in transforms include `Identity`, `Base64Transform`, `HexTransform`,
`Rot13Transform`, `ReversedTransform`, `ZeroWidthTransform`, `HomoglyphTransform`,
`LeetspeakTransform`, `SpacedTransform`, `JsonWrapTransform`, `XmlWrapTransform`,
`MarkdownCommentTransform`, and `NoiseTransform`.

## For AI Agents

### Working In This Directory
- Add a transform by subclassing `Transform` (or `_WrappingTransform`) and
  registering it with a stable id (e.g. `encoding.base64`, `unicode.zero_width`).
- Encoding/decoding primitives live in `core/codecs.py` — reuse them rather than
  reimplementing.
- Transforms must be pure functions of their input plus the seeded RNG; keep them
  deterministic.

### Testing Requirements
- `uv run pytest tests/framework/test_transforms.py`.

### Common Patterns
- Transform ids follow a `category.name` convention used in reports and config.

## Dependencies

### Internal
- `core/codecs.py` (encodings), `core/` (RNG, data model).

<!-- MANUAL: -->

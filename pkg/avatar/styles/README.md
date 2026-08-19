# Vendored DiceBear style definitions

These two files are copied verbatim from
[`github.com/dicebear/styles`](https://github.com/dicebear/dicebear) v10.4.0,
`src/lorelei.json` and `src/loops.json`. They are pure data — the renderer
is `github.com/dicebear/dicebear-go/v10`, which is an ordinary module
dependency.

They are vendored rather than taken from `github.com/dicebear/styles/v10`
because that module's own package documentation says Go embeds *every* style it
ships into the consuming binary, with no per-style opt-in: four megabytes of
JSON in the phone app, for the two of them we draw.

Both are CC0 1.0, and each carries its own licence and attribution inside the
`meta` object, which the renderer copies into every drawing it makes:

- **Lorelei** — remix of
  [Lorelei](https://www.figma.com/community/file/1198749693280469639) by Lisa
  Wischofsky, [CC0 1.0](https://creativecommons.org/publicdomain/zero/1.0/).
- **Loops** — by DiceBear,
  [CC0 1.0](https://creativecommons.org/publicdomain/zero/1.0/).

Updating them means copying the newer files over and running
`go test ./pkg/avatar/` — including `TestAvatarDemo`, since a style change
can move a face out of the tile and no assertion will notice.

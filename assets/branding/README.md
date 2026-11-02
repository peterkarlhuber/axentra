# Axentra branding

## Provenance

`axentra-logo-transparent.png` and `axentra-logo-white.png` are the official Axentra logo masters
(2048 × 640 px, symbol left, black wordmark right), supplied by the brand owner (the owner of
this repository). The white master is the transparent one flattened on white. Do not edit the
masters, and do not edit the derived files by hand: regenerate them.

`derive_branding.py` is the shared derivation script, vendored unchanged in every repository that
ships the logo (axentra, axentra-studio, ...). It needs Python 3 with Pillow and NumPy and never
redraws the artwork: it only defringes the edges, recolors the wordmark to white for dark
surfaces, trims, pads and resamples.

## Files

| File | Size | Use |
| --- | --- | --- |
| `axentra-logo-transparent.png` | 2048 × 640 | Master, transparent background. Source of all derived files. |
| `axentra-logo-white.png` | 2048 × 640 | Master on white. Reference only (`--check` compares it). |
| `axentra-logo.png` | 960 × 238 | Lockup with black wordmark, for light surfaces (README). |
| `axentra-logo-on-dark.png` | 960 × 238 | Lockup with white wordmark, for dark surfaces (README in dark mode). |
| `axentra-mark.png` | 512 × 512 | Symbol only, transparent. |
| `social-preview.png` | 1280 × 640 | GitHub social preview (uploaded manually in the repository settings). |

## Regenerate

```bash
cd assets/branding
python3 derive_branding.py --product axentra --masters . --check
python3 derive_branding.py --product axentra --masters . --out . --sets web
rm axentra-mark-128.png   # not used in this repository
python3 social_preview.py --product axentra --masters . --out social-preview.png \
  --caption "Modular backend foundation for SaaS products"
```

`social_preview.py` is the GitHub social preview template shared with the Nodestro and Orkexa
repositories (vendored unchanged next to `derive_branding.py`): a dark background with a soft
glow in the brand violet, the white-wordmark lockup, a short accent rule and a one-line
caption. Only the logo pixels come from the master; nothing is redrawn.

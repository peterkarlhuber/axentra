"""Lay out the 1280 x 640 GitHub social preview for a Nodestro, Orkexa or Axentra repository.

One shared template for all three brands: a dark brand background with a soft glow of the
brand colour behind the symbol, the official lockup with the white (on-dark) wordmark, an
optional product tag (for example "Studio") and a one-line caption. Every logo pixel comes
from ``derive_branding.variants`` (vendored next to this file); nothing is redrawn.

    python social_preview.py --product axentra --masters <folder> --out social-preview.png \
        --caption "Modular backend foundation for SaaS products" [--tag Studio]

Needs Pillow (with FreeType) and NumPy. The text face is Pillow's bundled default font, so no
font file is vendored. Output bytes depend on the Pillow version, like derive_branding.py.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

import numpy as np
from PIL import Image, ImageDraw, ImageFont

sys.path.insert(0, str(Path(__file__).resolve().parent))
import derive_branding  # vendored next to this file, after the sys.path entry above

SIZE = (1280, 640)
LOCKUP_WIDTH = 720
#: Height below the lockup taken by the accent rule and the caption line.
CAPTION_BLOCK = 46 + 4 + 30 + 30

#: Per brand: background top and bottom, glow colour (the symbol's main hue), caption colour.
THEMES = {
    "nodestro": {
        "top": (24, 28, 30),
        "bottom": (13, 15, 17),
        "glow": (168, 200, 40),
        "strength": 0.22,
        "text": (190, 211, 114),
    },
    "orkexa": {
        "top": (22, 28, 40),
        "bottom": (8, 11, 19),
        "glow": (0, 120, 248),
        "strength": 0.16,
        "text": (150, 190, 240),
    },
    "axentra": {
        "top": (26, 23, 96),
        "bottom": (11, 9, 52),
        "glow": (120, 72, 248),
        "strength": 0.30,
        "text": (200, 204, 239),
    },
}


def background(theme: dict, glow_center: tuple[float, float]) -> Image.Image:
    w, h = SIZE
    y = np.linspace(0.0, 1.0, h)[:, None, None]
    top = np.array(theme["top"], dtype=np.float64)
    bottom = np.array(theme["bottom"], dtype=np.float64)
    rgb = np.broadcast_to(top + (bottom - top) * y, (h, w, 3)).copy()
    yy, xx = np.mgrid[0:h, 0:w]
    gx, gy = glow_center
    dist = np.hypot((xx - gx) / 520.0, (yy - gy) / 360.0)
    strength = (theme["strength"] * np.exp(-(dist**2) * 2.2))[..., None]
    rgb = rgb * (1 - strength) + np.array(theme["glow"], dtype=np.float64) * strength
    # Faint dot grid, the same rhythm on every brand.
    dots = ((xx % 32) == 16) & ((yy % 32) == 16)
    rgb[dots] = rgb[dots] * 0.9 + 255 * 0.1
    return Image.fromarray(np.clip(rgb + 0.5, 0, 255).astype(np.uint8), "RGB").convert("RGBA")


def spaced_text(draw, xy, text, font, fill, tracking):
    x, y = xy
    for ch in text:
        draw.text((x, y), ch, font=font, fill=fill)
        x += draw.textlength(ch, font=font) + tracking


def spaced_width(draw, text, font, tracking):
    return sum(draw.textlength(ch, font=font) for ch in text) + tracking * (len(text) - 1)


def compose(product: str, masters: Path, caption: str, tag: str | None) -> Image.Image:
    theme = THEMES[product]
    v = derive_branding.variants(product, masters)
    lockup = derive_branding.lockup(v["on_dark"], LOCKUP_WIDTH)
    w, h = SIZE
    tag_font = ImageFont.load_default(34)
    cap_font = ImageFont.load_default(30)
    probe = ImageDraw.Draw(Image.new("RGB", (1, 1)))
    tag_w = round(spaced_width(probe, tag.upper(), tag_font, 6)) + 40 if tag else 0
    group_w = lockup.width + (28 + tag_w if tag else 0)
    x0 = (w - group_w) // 2
    # Centre the whole block (lockup, rule, caption) vertically.
    block_h = lockup.height + (CAPTION_BLOCK if caption else 0)
    y0 = (h - block_h) // 2
    split = derive_branding.split_column(np.asarray(v["on_dark"]))
    symbol_cx = x0 + lockup.width * split / v["on_dark"].width / 2
    img = background(theme, (symbol_cx, y0 + lockup.height / 2))
    img.alpha_composite(lockup, (x0, y0))
    draw = ImageDraw.Draw(img)
    if tag:
        tx = x0 + lockup.width + 28
        ty = y0 + lockup.height // 2 - 30
        draw.rounded_rectangle((tx, ty, tx + tag_w, ty + 60), radius=12, outline=theme["glow"], width=3)
        spaced_text(draw, (tx + 20, ty + 11), tag.upper(), tag_font, (255, 255, 255), 6)
    if caption:
        rule_y = y0 + lockup.height + 46
        draw.rounded_rectangle((w // 2 - 32, rule_y, w // 2 + 32, rule_y + 4), radius=2, fill=theme["glow"])
        cw = draw.textlength(caption, font=cap_font)
        draw.text(((w - cw) / 2, rule_y + 30), caption, font=cap_font, fill=theme["text"])
    return img.convert("RGB")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--product", required=True, choices=sorted(THEMES))
    ap.add_argument("--masters", type=Path, required=True, help="folder with the two master PNGs")
    ap.add_argument("--out", type=Path, required=True, help="output PNG")
    ap.add_argument("--caption", default="", help="one-line caption below the logo")
    ap.add_argument("--tag", help="optional product tag next to the lockup, e.g. Studio")
    args = ap.parse_args(argv)
    img = compose(args.product, args.masters, args.caption, args.tag)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    img.save(args.out, optimize=True)
    print(f"wrote {args.out} {img.size[0]}x{img.size[1]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

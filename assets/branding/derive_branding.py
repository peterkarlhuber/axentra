#!/usr/bin/env python3
"""Derive every logo, icon and favicon variant from the official logo masters.

The masters are the two files supplied by the brand owner for each product:

* ``<product>-logo-transparent.png`` - 2048 x 640, transparent background, black wordmark
* ``<product>-logo-white.png``       - the same artwork on a solid white background

All derived files are produced from the transparent master only (the white master is
that same artwork flattened on white; ``--check`` verifies this). Nothing is redrawn:
the symbol keeps its exact pixels, shapes, colours and proportions. The only pixel
operations are:

1. **Defringe** - semi-transparent edge pixels left over from the background knockout
   carry a light halo; their colour is replaced by the colour of the nearest opaque
   pixel of the same shape (alpha unchanged), so no light seam shows on dark surfaces.
2. **Reversed wordmark** - for dark surfaces the black wordmark is recoloured to
   white. Alpha (and so the letter shapes and anti-aliasing) is unchanged.
3. **Dark-surface symbol (Orkexa only)** - the Orkexa symbol fades into deep navy, which
   disappears on dark backgrounds. Its on-dark variant raises the lightness of the
   darkest tones (hue and saturation unchanged, the bright blue accents untouched).
4. Trimming to the artwork, square padding, resampling (Lanczos) and format export.

Usage::

    python derive_branding.py --product nodestro --masters DIR --out DIR [--sets web,desktop]
    python derive_branding.py --product orkexa --masters DIR --check

The same script is vendored unchanged in every repository that ships one of the logos
(nodestro-studio, nodestro-desktop, orkexa, axentra, axentra-studio). Requires Pillow
and NumPy only.
"""

from __future__ import annotations

import argparse
import colorsys
import itertools
import json
from pathlib import Path
import sys

import numpy as np
from PIL import Image

#: Colour of the wordmark on dark surfaces.
REVERSED_WORDMARK = (255, 255, 255)

#: Per product: background of opaque app-icon tiles (home screen, maskable, desktop),
#: and whether the symbol needs the lifted dark-surface variant.
PRODUCTS = {
    "nodestro": {"tile": (14, 17, 22), "lift": None, "name": "Nodestro"},
    "orkexa": {"tile": (255, 255, 255), "lift": 0.45, "name": "Orkexa"},
    "axentra": {"tile": (255, 255, 255), "lift": None, "name": "Axentra"},
}

#: Minimum gap (px, in the 2048-px master) between symbol and wordmark.
SPLIT_GAP = 60


# --------------------------------------------------------------------------- pixel ops


def load_master(path: Path) -> np.ndarray:
    return np.array(Image.open(path).convert("RGBA")).astype(np.int32)


def to_image(arr: np.ndarray) -> Image.Image:
    return Image.fromarray(np.clip(arr, 0, 255).astype(np.uint8), "RGBA")


def split_column(arr: np.ndarray) -> int:
    """First x of the wordmark: the start of the first wide transparent column gap."""
    cols = np.where((arr[..., 3] > 0).any(axis=0))[0]
    for left, right in itertools.pairwise(cols):
        if right - left > SPLIT_GAP:
            return int(left + right) // 2
    raise SystemExit("could not find the gap between symbol and wordmark")


def defringe(arr: np.ndarray) -> np.ndarray:
    """Replace the colour of non-opaque pixels with that of the nearest opaque pixel."""
    out = arr.copy()
    known = arr[..., 3] == 255
    rgb = arr[..., :3].astype(np.float64) * known[..., None]
    weight = known.astype(np.float64)
    todo = (arr[..., 3] > 0) & ~known
    for _ in range(12):
        if not todo.any():
            break
        acc = np.zeros_like(rgb)
        cnt = np.zeros_like(weight)
        for dy in (-1, 0, 1):
            for dx in (-1, 0, 1):
                if dy == 0 and dx == 0:
                    continue
                acc += np.roll(np.roll(rgb, dy, 0), dx, 1)
                cnt += np.roll(np.roll(weight, dy, 0), dx, 1)
        fill = todo & (cnt > 0)
        rgb[fill] = acc[fill] / cnt[fill][:, None]
        weight[fill] = 1.0
        todo &= ~fill
    # Anything isolated (no opaque neighbour within reach) keeps its own colour.
    mask = (arr[..., 3] > 0) & (arr[..., 3] < 255) & (weight > 0)
    out[..., :3][mask] = np.rint(rgb[mask] / weight[mask][:, None]).astype(np.int32)
    return out


def recolor(arr: np.ndarray, x0: int, color: tuple[int, int, int]) -> np.ndarray:
    out = arr.copy()
    region = out[:, x0:]
    visible = region[..., 3] > 0
    region[..., :3][visible] = color
    return out


def lift_dark_tones(arr: np.ndarray, x1: int, floor: float) -> np.ndarray:
    """Raise the HLS lightness of dark symbol pixels left of ``x1`` (hue, saturation kept)."""
    out = arr.copy()
    ys, xs = np.where(out[:, :x1, 3] > 0)
    for y, x in zip(ys, xs, strict=False):
        r, g, b = (out[y, x, :3] / 255.0).tolist()
        h, light, s = colorsys.rgb_to_hls(r, g, b)
        if light >= floor:
            continue
        target = max(light, floor * 0.55 + light * 0.45)
        nr, ng, nb = colorsys.hls_to_rgb(h, target, s)
        out[y, x, :3] = [round(nr * 255), round(ng * 255), round(nb * 255)]
    return out


def bbox(arr: np.ndarray) -> tuple[int, int, int, int]:
    ys, xs = np.where(arr[..., 3] > 0)
    return int(xs.min()), int(ys.min()), int(xs.max()) + 1, int(ys.max()) + 1


def trim(img: Image.Image, pad_ratio: float = 0.0) -> Image.Image:
    box = img.getbbox()
    crop = img.crop(box)
    if not pad_ratio:
        return crop
    pad = round(crop.height * pad_ratio)
    canvas = Image.new("RGBA", (crop.width + 2 * pad, crop.height + 2 * pad), (0, 0, 0, 0))
    canvas.alpha_composite(crop, (pad, pad))
    return canvas


def square(mark: Image.Image, size: int, fill: float, tile=None, radius: float = 0.0) -> Image.Image:
    """Centre the trimmed symbol on a square canvas; ``fill`` = share of the edge it spans."""
    mark = trim(mark)
    scale = fill * size / max(mark.size)
    w, h = max(1, round(mark.width * scale)), max(1, round(mark.height * scale))
    # Downscale in steps for crisp small icons.
    resized = mark.resize((w, h), Image.LANCZOS, reducing_gap=3.0)
    canvas = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    if tile is not None:
        bg = Image.new("RGBA", (size, size), (*tuple(tile), 255))
        if radius:
            mask = Image.new("L", (size * 4, size * 4), 0)
            from PIL import ImageDraw

            ImageDraw.Draw(mask).rounded_rectangle(
                (0, 0, size * 4 - 1, size * 4 - 1), radius=round(radius * size * 4), fill=255
            )
            bg.putalpha(mask.resize((size, size), Image.LANCZOS))
        canvas = bg
    canvas.alpha_composite(resized, ((size - w) // 2, (size - h) // 2))
    return canvas


def lockup(img: Image.Image, width: int) -> Image.Image:
    t = trim(img)
    return t.resize((width, round(t.height * width / t.width)), Image.LANCZOS)


def flatten(img: Image.Image, color=(255, 255, 255)) -> Image.Image:
    bg = Image.new("RGBA", img.size, (*tuple(color), 255))
    bg.alpha_composite(img)
    return bg.convert("RGB")


# --------------------------------------------------------------------------- variants


def variants(product: str, masters: Path) -> dict[str, Image.Image]:
    cfg = PRODUCTS[product]
    raw = load_master(masters / f"{product}-logo-transparent.png")
    split = split_column(raw)
    clean = defringe(raw)
    dark_symbol = lift_dark_tones(clean, split, cfg["lift"]) if cfg["lift"] else clean
    light = to_image(clean)
    on_dark = to_image(recolor(dark_symbol, split, REVERSED_WORDMARK))
    mark = to_image(clean[:, :split].copy())
    mark_dark = to_image(dark_symbol[:, :split].copy())
    return {"light": light, "on_dark": on_dark, "mark": mark, "mark_on_dark": mark_dark}


def write_png(img: Image.Image, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    img.save(path, optimize=True)
    return path


def build_web(product: str, v: dict[str, Image.Image], out: Path, lockup_width: int) -> list[Path]:
    """Lockups, symbol, favicons, home-screen and web-app icons."""
    cfg = PRODUCTS[product]
    p = product
    files = [
        write_png(lockup(v["light"], lockup_width), out / f"{p}-logo.png"),
        write_png(lockup(v["on_dark"], lockup_width), out / f"{p}-logo-on-dark.png"),
        write_png(square(v["mark"], 512, 0.92), out / f"{p}-mark.png"),
        write_png(square(v["mark"], 128, 0.94), out / f"{p}-mark-128.png"),
    ]
    if cfg["lift"]:
        # Only symbols with a dark-surface variant get one; the others use -mark on any surface.
        files.append(write_png(square(v["mark_on_dark"], 512, 0.92), out / f"{p}-mark-on-dark.png"))
        files.append(write_png(square(v["mark_on_dark"], 128, 0.94), out / f"{p}-mark-on-dark-128.png"))
    return files


def build_favicons(product: str, v: dict[str, Image.Image], out: Path) -> list[Path]:
    cfg = PRODUCTS[product]
    tile = cfg["tile"]
    # Browser tabs can be light or dark: products whose symbol needs a light surface get a
    # rounded tile, the others a transparent background.
    tab_tile = tile if cfg["lift"] else None
    radius = 0.22 if tab_tile else 0.0
    fill = 0.80 if tab_tile else 0.98
    out.mkdir(parents=True, exist_ok=True)
    ico_frames = [square(v["mark"], s, fill, tab_tile, radius) for s in (16, 32, 48)]
    ico = out / "favicon.ico"
    ico_frames[-1].save(ico, sizes=[(16, 16), (32, 32), (48, 48)], append_images=ico_frames[:-1])
    return [
        ico,
        write_png(ico_frames[0], out / "favicon-16.png"),
        write_png(ico_frames[1], out / "favicon-32.png"),
        # iOS draws its own rounded corners and needs an opaque square.
        write_png(flatten(square(v["mark"], 180, 0.72, tile)), out / "apple-touch-icon.png"),
        write_png(square(v["mark"], 192, 0.90), out / "icon-192.png"),
        write_png(square(v["mark"], 512, 0.90), out / "icon-512.png"),
        # Maskable: the symbol stays inside the 80 % safe zone (a circle of radius 0.4).
        write_png(flatten(square(v["mark"], 512, 0.56, tile)), out / "icon-maskable-512.png"),
    ]


def build_desktop(product: str, v: dict[str, Image.Image], out: Path) -> list[Path]:
    """Tauri bundle icons (Windows .ico, macOS .icns, Linux PNGs)."""
    tile = PRODUCTS[product]["tile"]
    out.mkdir(parents=True, exist_ok=True)

    # macOS/Windows app icons: rounded tile with ~10 % transparent margin (Apple grid).
    def app(size: int) -> Image.Image:
        inner = round(size * 0.80)
        tile_img = square(v["mark"], inner, 0.70, tile, 0.225)
        canvas = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        canvas.alpha_composite(tile_img, ((size - inner) // 2, (size - inner) // 2))
        return canvas

    files = [
        write_png(app(32), out / "32x32.png"),
        write_png(app(128), out / "128x128.png"),
        write_png(app(256), out / "128x128@2x.png"),
        write_png(app(512), out / "icon.png"),
    ]
    # Windows: small sizes show the bare symbol (a tile shrinks it too far at 16-32 px).
    frames = [square(v["mark"], s, 0.96) if s <= 32 else app(s) for s in (16, 24, 32, 48, 64, 128, 256)]
    ico = out / "icon.ico"
    frames[-1].save(ico, sizes=[f.size for f in frames], append_images=frames[:-1])
    icns = out / "icon.icns"
    app(1024).save(icns)
    return [*files, ico, icns]


def check(product: str, masters: Path) -> list[str]:
    """Assert the masters are what this script expects."""
    problems = []
    t = load_master(masters / f"{product}-logo-transparent.png")
    w = np.array(Image.open(masters / f"{product}-logo-white.png").convert("RGB")).astype(np.float64)
    if t.shape[:2] != (640, 2048):
        problems.append(f"{product}: transparent master is {t.shape[1]}x{t.shape[0]}, expected 2048x640")
    a = t[..., 3:4] / 255.0
    composite = t[..., :3] * a + 255 * (1 - a)
    diff = np.abs(composite - w).max()
    if diff > 1.0:
        problems.append(f"{product}: white master differs from transparent-on-white by {diff:.1f}")
    split = split_column(t)
    word = t[:, split:]
    colours = np.unique(word[word[..., 3] > 0][:, :3], axis=0)
    if len(colours) != 1 or tuple(colours[0]) != (0, 0, 0):
        problems.append(f"{product}: wordmark is not pure black ({len(colours)} colours)")
    return problems


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--product", required=True, choices=sorted(PRODUCTS))
    ap.add_argument("--masters", type=Path, required=True, help="folder with the two master PNGs")
    ap.add_argument("--out", type=Path, help="output folder")
    ap.add_argument("--sets", default="web,favicons", help="comma list of web, favicons, desktop")
    ap.add_argument("--lockup-width", type=int, default=960)
    ap.add_argument("--favicon-out", type=Path, help="favicons folder (default: --out)")
    ap.add_argument("--check", action="store_true", help="only verify the masters")
    args = ap.parse_args(argv)

    problems = check(args.product, args.masters)
    if problems or args.check:
        print("\n".join(problems) or f"{args.product}: masters OK")
        return 1 if problems else 0
    if not args.out:
        ap.error("--out is required unless --check is given")
    v = variants(args.product, args.masters)
    written: list[Path] = []
    sets = {s.strip() for s in args.sets.split(",") if s.strip()}
    if "web" in sets:
        written += build_web(args.product, v, args.out, args.lockup_width)
    if "favicons" in sets:
        written += build_favicons(args.product, v, args.favicon_out or args.out)
    if "desktop" in sets:
        written += build_desktop(args.product, v, args.out)
    print(json.dumps([str(p) for p in written], indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())

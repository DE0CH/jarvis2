#!/usr/bin/env python3
"""Draw the Jarvis app icon (an arc-reactor ring) -> assets/icon.png (app.json "icon"; Expo makes the iOS icon set from it).
1024x1024 RGB, no alpha (App Store rejects alpha). Rendered at 2x and downsampled for smooth edges.
The web page's favicons are the ring alone on a transparent background, no square tile (Deyao, 2026-09-30):
assets/favicon.png (app.json web.favicon → Expo's favicon.ico) and public/icon-*.png. The home-screen
apple-touch-icon stays the full square icon (iOS draws it as a tile and fills transparency with black)."""
import math, os
from PIL import Image, ImageDraw, ImageFilter

S = 2048; C = S / 2
img = Image.new("RGB", (S, S), (8, 14, 26))
bg = Image.new("RGB", (S, S)); d = ImageDraw.Draw(bg)
for r in range(int(S * 0.75), 0, -8):               # radial background glow
    t = r / (S * 0.75)
    d.ellipse([C - r, C - r, C + r, C + r], fill=(int(8 + 22 * (1 - t) ** 2), int(14 + 50 * (1 - t) ** 2), int(26 + 70 * (1 - t) ** 2)))
img = bg

glow = Image.new("RGB", (S, S)); g = ImageDraw.Draw(glow)
CYAN = (110, 225, 255)
def ring(dr, r, w, col):
    dr.ellipse([C - r, C - r, C + r, C + r], outline=col, width=w)
ring(g, 720, 60, CYAN)                                   # outer ring
for i in range(10):                                      # ten coil segments
    a0 = i * 36 + 4; a1 = a0 + 28
    g.arc([C - 600, C - 600, C + 600, C + 600], a0, a1, fill=CYAN, width=120)
ring(g, 430, 40, CYAN)
tri = [(C + 380 * math.cos(math.radians(a)), C + 380 * math.sin(math.radians(a))) for a in (-90, 30, 150)]
g.polygon(tri, outline=CYAN, width=48)                   # the inner triangle
g.ellipse([C - 110, C - 110, C + 110, C + 110], fill=(200, 245, 255))   # core
blur = glow.filter(ImageFilter.GaussianBlur(40))
img = Image.blend(img, Image.eval(blur, lambda v: min(255, v)), 0.55)
img.paste(glow, (0, 0), glow.convert("L").point(lambda v: 255 if v > 20 else 0))
img = img.resize((1024, 1024), Image.LANCZOS).convert("RGB")
out = os.path.join(os.path.dirname(__file__), "..", "assets", "icon.png")
img.save(out, optimize=True); print("wrote", os.path.normpath(out))
pub = os.path.join(os.path.dirname(__file__), "..", "public")
img.resize((180, 180), Image.LANCZOS).save(os.path.join(pub, "apple-touch-icon.png"), optimize=True)
# favicons: the ring alone — its shapes plus their soft glow as alpha — cropped to the ring
ringimg = Image.new("RGBA", (S, S), (0, 0, 0, 0))
# the glow in the ring's own cyan (its blurred RGB would show as a grey smudge on a light tab bar)
halo = Image.new("RGBA", (S, S), CYAN + (0,)); halo.putalpha(blur.convert("L").point(lambda v: min(255, int(v * 0.7))))
ringimg.alpha_composite(halo)
ringimg.paste(glow, (0, 0), glow.convert("L").point(lambda v: 255 if v > 20 else 0))
R = 800
ringimg = ringimg.crop((int(C - R), int(C - R), int(C + R), int(C + R)))
ringimg.resize((512, 512), Image.LANCZOS).save(os.path.join(os.path.dirname(__file__), "..", "assets", "favicon.png"), optimize=True)
for name, px in (("icon-192.png", 192), ("icon-512.png", 512)):
    ringimg.resize((px, px), Image.LANCZOS).save(os.path.join(pub, name), optimize=True)

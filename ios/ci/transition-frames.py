#!/usr/bin/env python3
"""Cut transitions.yml's screen recording into one frame sheet per secure-mode switch.

usage: transition-frames.py <artifact dir> <light|dark> <out dir> [--before 2.2] [--after 1.5] [--width 300]

The artifact dir is transitions.yml's `transitions` artifact: transitions-<a>.mov (simctl recordVideo, which writes a
frame whenever the screen changes, so its frames are every distinct picture that was on screen), video-<a>.start (the
wall-clock time the recorder was launched), <a>/*.txt (TransitionsUITests' marks: each marked tap's time and name)
and sim.log (the shell's own "enter secure"/"exit secure" lines, the runner's clock).

Every frame is decoded once (scaled to --width) into <out>/<a>-frames/NNNN.png. Each mark is snapped to the shell's
log line for it, and the frames from `before` s ahead of it to `after` s past it become a labelled sheet
<out>/<a>-<name>.png (labels: ms from the shell's event, as placed on the video; the first tile is the picture
already on screen). The recorder's frames lag the runner's clock by 1–2 s (--offset) and the lag drifts, so the
default window is generous. Needs ffmpeg/ffprobe and Pillow.
"""
import argparse, datetime, glob, json, os, subprocess
from PIL import Image, ImageDraw, ImageFont

ap = argparse.ArgumentParser()
ap.add_argument("art"); ap.add_argument("appearance"); ap.add_argument("out")
ap.add_argument("--before", type=float, default=2.2); ap.add_argument("--after", type=float, default=1.5)
ap.add_argument("--width", type=int, default=300)
ap.add_argument("--tile", type=int, default=150, help="width of a frame on the sheet")
ap.add_argument("--offset", type=float, default=1.2)
ap.add_argument("--only", default="", help="comma-separated mark names")
a = ap.parse_args()

video = os.path.join(a.art, f"transitions-{a.appearance}.mov")
start = float(open(os.path.join(a.art, f"video-{a.appearance}.start")).read().strip())
marks_file = next(iter(sorted(glob.glob(os.path.join(a.art, a.appearance, "*.txt")))), None)
if not marks_file:
    raise SystemExit("no marks attachment under " + os.path.join(a.art, a.appearance))
marks = []
for line in open(marks_file):
    if line.strip():
        t, name = line.split(" ", 1); marks.append((float(t), name.strip()))
if a.only:
    marks = [m for m in marks if m[1] in a.only.split(",")]

events = []
simlog = os.path.join(a.art, "sim.log")
if os.path.exists(simlog):
    for line in open(simlog, errors="replace"):
        if "[shell]" in line and ("enter secure" in line or "exit secure" in line):
            try:
                events.append(datetime.datetime.strptime(line[:23], "%Y-%m-%d %H:%M:%S.%f")
                              .replace(tzinfo=datetime.timezone.utc).timestamp())
            except ValueError:
                pass

probe = subprocess.run(["ffprobe", "-v", "error", "-select_streams", "v:0", "-show_entries", "frame=pts_time",
                        "-of", "json", video], capture_output=True, text=True, check=True)
pts = [float(f["pts_time"]) for f in json.loads(probe.stdout)["frames"] if "pts_time" in f]
fd = os.path.join(a.out, f"{a.appearance}-frames")
os.makedirs(fd, exist_ok=True)
if len(glob.glob(os.path.join(fd, "*.png"))) != len(pts):
    for f in glob.glob(os.path.join(fd, "*.png")): os.remove(f)
    subprocess.run(["ffmpeg", "-v", "error", "-i", video, "-vf", f"scale={a.width}:-2", "-fps_mode", "passthrough",
                    "-start_number", "0", os.path.join(fd, "%04d.png")], check=True)
font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 13)

for wall, name in marks:
    ev = next((e for e in events if wall - 0.5 <= e <= wall + 4), wall)
    t = ev - start - a.offset
    sel = [i for i, p in enumerate(pts) if t - a.before <= p <= t + a.after]
    prev = [i for i, p in enumerate(pts) if p < t - a.before]
    if prev: sel = [prev[-1]] + sel
    if not sel:
        print(name, "no frames"); continue
    ims = [Image.open(os.path.join(fd, f"{i:04d}.png")) for i in sel]
    w = a.tile; h = int(ims[0].height * w / ims[0].width)
    cols = min(10, len(ims)); rows = (len(ims) + cols - 1) // cols
    sheet = Image.new("RGB", (cols * (w + 6) + 6, rows * (h + 24) + 6), (110, 110, 110))
    dr = ImageDraw.Draw(sheet)
    for k, (im, i) in enumerate(zip(ims, sel)):
        x = 6 + (k % cols) * (w + 6); y = 6 + (k // cols) * (h + 24)
        sheet.paste(im.convert("RGB").resize((w, h)), (x, y + 18))
        dr.text((x, y), f"{(pts[i] - t) * 1000:+.0f}ms", fill=(255, 255, 255), font=font)
    sheet.save(os.path.join(a.out, f"{a.appearance}-{name}.png"))
    print(f"{name}: {len(sel)} frames around video t={t:.2f}s")

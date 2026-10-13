"""Turn one iCloud file into searchable text parts: [(part, src, text)].

  part  where in the file ("p3" = page 3, "slide 2", "00:04:10" = a video/audio timestamp, a zip member)
  src   text (the file's own text) | ocr (a scanned page read by the vision model) | vision (an image:
        its text + a description) | frames (what is on screen in a video) | speech (transcript) |
        members (names inside an archive) | meta

Local extraction is free; the AI steps (images, scanned pages, video frames, speech) go through
ctx.ai(), which serves them from the content cache, checks the budget, and books the cost.
"""
import email, email.policy, hashlib, html, io, json, os, re, subprocess, tarfile, zipfile

from . import ai

TEXT_EXT = set("txt md markdown tex bib csv tsv log ini cfg conf toml yml yaml json xml html htm xhtml svg srt vtt ass py js ts jsx tsx java c h cc cpp hpp cs go rs rb php pl sh bash zsh swift kt m mm r sql lua scala hs ml css scss less vcf ics rtf ipynb eml tex sty cls rst org nfo".split())
OFFICE_EXT = {"docx", "docm", "dotx", "pptx", "ppsx", "xlsx", "xlsm", "odt", "odp", "ods"}
LEGACY_EXT = {"doc", "xls", "ppt"}
IWORK_EXT = {"pages", "numbers", "key"}
IMAGE_EXT = {"jpg", "jpeg", "png", "heic", "heif", "gif", "bmp", "tif", "tiff", "webp", "jfif"}
RAW_EXT = {"raf", "dng", "cr2", "cr3", "nef", "arw", "orf", "rw2", "srw", "pef"}
PSD_EXT = {"psd", "psb"}
VIDEO_EXT = {"mov", "mp4", "m4v", "avi", "mkv", "3gp", "mts", "m2ts", "wmv", "webm", "flv", "mpg", "mpeg", "vob"}
AUDIO_EXT = {"mp3", "m4a", "wav", "aac", "flac", "ogg", "opus", "amr", "wma", "aiff", "aif", "caf", "m4b"}
ARCHIVE_EXT = {"zip", "rar", "7z", "tar", "tgz", "gz", "bz2", "xz"}

MAX_TEXT_BYTES = int(os.environ.get("MAX_TEXT_BYTES", str(4 << 20)))
MAX_DOC_BYTES = int(os.environ.get("MAX_DOC_BYTES", str(1 << 30)))       # PDFs / office / images: download cap
MAX_ARCHIVE_BYTES = int(os.environ.get("MAX_ARCHIVE_BYTES", str(4 << 30)))
MAX_OCR_PAGES = int(os.environ.get("MAX_OCR_PAGES", "150"))
MAX_FRAMES = int(os.environ.get("MAX_FRAMES", "60"))
FRAMES_PER_CALL = 10
IMG_MAX_SIDE = int(os.environ.get("IMG_MAX_SIDE", "1600"))
MAX_IMAGE_PIXELS = int(os.environ.get("MAX_IMAGE_PIXELS", "40000000"))
# folders whose contents are software, not documents: names are indexed, contents are not read
SKIP_DIRS = re.compile(r"(^|/)(\.git|node_modules|__pycache__|\.anaconda|anaconda3|miniconda3|site-packages|\.cache|\.npm|\.gradle|\.m2|\.cargo|\.rustup|\.android|\.vscode|\.idea|venv|\.venv|[^/]+\.app|[^/]+\.framework|[^/]+\.bundle|\.Trash)(/|$)", re.I)


class NeedBudget(Exception):
    """An AI step is needed but the budget is used up: the file waits (state wait-ai)."""


def ext_of(path):
    n = path.rsplit("/", 1)[-1]
    return n.rsplit(".", 1)[-1].lower() if "." in n.strip(".") else ""


def kind_of(path, size):
    """-> (kind, prio). Lower prio = extracted sooner (documents first, big videos last)."""
    e = ext_of(path)
    top = path.split("/", 1)[0]
    near = 0 if top in ("Documents", "Desktop", "Downloads") else 1
    if SKIP_DIRS.search(path):
        return "other", 9
    if e == "pdf": return "pdf", 0 + near
    if e in OFFICE_EXT or e in LEGACY_EXT: return "office", 0 + near
    if e in IWORK_EXT: return "iwork", 1 + near
    if e in TEXT_EXT: return ("text", 1 + near) if size <= MAX_TEXT_BYTES else ("other", 9)
    if e in IMAGE_EXT: return "image", 2 + near
    if e in PSD_EXT: return "image", 3 + near
    if e in RAW_EXT: return "raw", 4 + near
    if e in AUDIO_EXT: return "audio", 4 + near
    if e in ARCHIVE_EXT: return "archive", 3 + near
    if e in VIDEO_EXT: return "video", 5 + near
    return "other", 9


# ---------------------------------------------------------------- helpers
def decode(b):
    for enc in ("utf-8", "utf-16") if b[:2] in (b"\xff\xfe", b"\xfe\xff") else ("utf-8",):
        try: return b.decode(enc)
        except UnicodeDecodeError: pass
    try:
        from charset_normalizer import from_bytes
        best = from_bytes(b[:200000]).best()
        if best: return b.decode(best.encoding, errors="replace")
    except Exception:
        pass
    return b.decode("gb18030", errors="replace")


TAG = re.compile(r"<[^>]+>")
def strip_markup(s):
    s = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", s)
    s = re.sub(r"(?i)</(p|div|h\d|li|tr|br|title|w:p|a:p|text:p|text:h)>|<br\s*/?>|<w:br/>|<w:tab/>", "\n", s)
    return html.unescape(TAG.sub(" ", s))


def tidy(s):
    s = re.sub(r"[ \t ]+", " ", s or "")
    return re.sub(r"\n\s*\n\s*\n+", "\n\n", s).strip()


def jpeg(img, side=IMG_MAX_SIDE):
    from PIL import Image
    if getattr(img, "n_frames", 1) > 1:
        img.seek(0)
    if img.mode in ("RGBA", "LA", "P"):
        img = img.convert("RGBA"); bg = Image.new("RGB", img.size, "white"); bg.paste(img, mask=img.split()[-1]); img = bg
    img = img.convert("RGB"); img.thumbnail((side, side))
    b = io.BytesIO(); img.save(b, "JPEG", quality=85); return b.getvalue()


def open_image(path_or_bytes):
    from PIL import Image, ImageOps
    try:
        import pillow_heif; pillow_heif.register_heif_opener()
    except ImportError:
        pass
    img = Image.open(io.BytesIO(path_or_bytes) if isinstance(path_or_bytes, bytes) else path_or_bytes)
    # a huge image decodes to w*h*4 bytes and more per copy (a 95-megapixel scan took the pod past its memory
    # limit on every restart): JPEGs are decoded at a reduced scale, anything else that big is not read
    if img.width * img.height > MAX_IMAGE_PIXELS:
        if img.format == "JPEG":
            img.draft("RGB", (IMG_MAX_SIDE * 2, IMG_MAX_SIDE * 2))
        if img.width * img.height > MAX_IMAGE_PIXELS:
            raise ValueError(f"image too large to read ({img.width}x{img.height})")
    try: img = ImageOps.exif_transpose(img)
    except Exception: pass
    return img


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""): h.update(b)
    return h.hexdigest()


def vision_parts(ctx, ckey, stage, jpg, hint, part, src="vision"):
    r = ctx.ai(ckey, stage, lambda: ai.read_image(jpg, hint))
    out = []
    body = "\n".join(x for x in (r.get("description"), r.get("keywords_zh")) if x)
    if r.get("text"): out.append((part, "ocr" if src == "ocr" else src, r["text"] + ("\n\n" + body if body else "")))
    elif body: out.append((part, src, body))
    return out


# ---------------------------------------------------------------- per kind
def ex_text(ctx, f, local):
    e = f["ext"]; b = open(local, "rb").read(MAX_TEXT_BYTES)
    if e == "eml":
        m = email.message_from_bytes(b, policy=email.policy.default)
        head = "\n".join(f"{k}: {m.get(k)}" for k in ("From", "To", "Cc", "Date", "Subject") if m.get(k))
        body = m.get_body(preferencelist=("plain", "html"))
        txt = body.get_content() if body else ""
        if body and body.get_content_type() == "text/html": txt = strip_markup(txt)
        names = [p.get_filename() for p in m.iter_attachments() if p.get_filename()]
        return [("", "text", tidy(head + "\n\n" + txt + ("\n\nAttachments: " + ", ".join(names) if names else "")))], None
    s = decode(b)
    if e == "ipynb":
        try: s = "\n\n".join("".join(c.get("source") or []) for c in json.loads(s).get("cells", []))
        except Exception: pass
    elif e in ("html", "htm", "xhtml", "xml", "svg"): s = strip_markup(s)
    elif e == "rtf":
        try:
            from striprtf.striprtf import rtf_to_text; s = rtf_to_text(s)
        except Exception: pass
    return [("", "text", tidy(s))], None


def ex_pdf(ctx, f, local):
    import pymupdf
    parts, ocr_pages = [], 0
    doc = pymupdf.open(local)
    if doc.needs_pass:
        return [], "password-protected PDF"
    note = None
    for i, pg in enumerate(doc):
        t = pg.get_text().strip()
        if len(t) >= 40 or not (pg.get_images() or pg.get_drawings()):
            if t: parts.append((f"p{i+1}", "text", t))
            continue
        if ocr_pages >= MAX_OCR_PAGES:
            note = f"only the first {MAX_OCR_PAGES} scanned pages were read"; continue
        ocr_pages += 1
        pix = pg.get_pixmap(dpi=150)
        jpg = jpeg(open_image(pix.tobytes("png")))
        parts += vision_parts(ctx, f["ckey"], f"page{i+1}", jpg, f"page {i+1} of {f['name']}", f"p{i+1}", "ocr")
    return parts, note


def _ooxml_text(z, names):
    out = []
    for n in names:
        try: out.append(strip_markup(z.read(n).decode("utf-8", "replace")))
        except KeyError: pass
    return tidy("\n".join(out))


def ex_office(ctx, f, local):
    e = f["ext"]
    if e in LEGACY_EXT:
        cmd = {"doc": ["antiword", "-w", "0", local], "xls": ["xls2csv", local], "ppt": ["catppt", local]}[e]
        r = subprocess.run(cmd, capture_output=True, timeout=300)
        if r.returncode != 0 and e == "doc":
            r = subprocess.run(["catdoc", "-w", local], capture_output=True, timeout=300)
        return [("", "text", tidy(decode(r.stdout)))], None
    z = zipfile.ZipFile(local); names = z.namelist(); parts = []
    if e in ("pptx", "ppsx"):
        slides = sorted((n for n in names if re.match(r"ppt/slides/slide\d+\.xml$", n)), key=lambda n: int(re.findall(r"\d+", n)[-1]))
        for n in slides:
            t = _ooxml_text(z, [n])
            if t: parts.append((f"slide {re.findall(r'\d+', n)[-1]}", "text", t))
    elif e.startswith("xls"):
        t = _ooxml_text(z, ["xl/sharedStrings.xml"] + [n for n in names if n.startswith("xl/worksheets/sheet")])
        if t: parts.append(("", "text", t))
    elif e.startswith("od"):
        t = _ooxml_text(z, ["content.xml"])
        if t: parts.append(("", "text", t))
    else:
        t = _ooxml_text(z, ["word/document.xml"] + sorted(n for n in names if re.match(r"word/(header|footer|footnotes|endnotes)\d*\.xml$", n)))
        if t: parts.append(("", "text", t))
    # a document that is mostly pasted-in pictures (a scan in a .docx): read up to 5 of them
    if sum(len(p[2]) for p in parts) < 200:
        media = [n for n in names if re.search(r"/media/[^/]+\.(png|jpe?g|gif|bmp|tiff?)$", n, re.I)][:5]
        for i, n in enumerate(media):
            try: jpg = jpeg(open_image(z.read(n)))
            except Exception: continue
            parts += vision_parts(ctx, f["ckey"], f"media{i}", jpg, f"picture {i+1} inside {f['name']}", n.rsplit("/", 1)[-1], "ocr")
    return parts, None


def ex_iwork(ctx, f, local):
    """Modern iWork files keep text in snappy protobufs; their QuickLook preview is what is readable."""
    try: z = zipfile.ZipFile(local)
    except zipfile.BadZipFile: return [], "not a zip (old iWork or package)"
    names = z.namelist(); parts = []
    pdf = next((n for n in names if n.lower().endswith("preview.pdf")), None)
    if pdf:
        tmp = local + ".preview.pdf"; open(tmp, "wb").write(z.read(pdf))
        sub = dict(f, name=f["name"] + " (preview)")
        try: parts, _ = ex_pdf(ctx, sub, tmp)
        finally: os.remove(tmp)
        return parts, None
    prev = next((n for n in names if re.search(r"(^|/)(preview|thumbnail)[^/]*\.(jpe?g|png)$", n, re.I)), None)
    if prev:
        parts = vision_parts(ctx, f["ckey"], "preview", jpeg(open_image(z.read(prev))), f"first-page preview of {f['name']}", "preview")
    return parts, None if prev else "no preview inside"


def ex_image(ctx, f, local):
    img = open_image(local)
    meta = image_meta(img)
    parts = vision_parts(ctx, f["ckey"], "image", jpeg(img), f["name"], "")
    if meta: parts.append(("", "meta", meta))
    return parts, None


def image_meta(img):
    try:
        ex = img.getexif(); sub = ex.get_ifd(0x8769)
        when = sub.get(36867) or ex.get(306); cam = " ".join(x for x in (ex.get(271), ex.get(272)) if x)
        s = " ".join(x for x in ((f"Taken {when}" if when else ""), (f"with {cam}" if cam else "")) if x)
        return s.strip()
    except Exception:
        return ""


def ex_raw(ctx, f, local):
    for tag in ("-JpgFromRaw", "-PreviewImage", "-ThumbnailImage"):
        r = subprocess.run(["exiftool", "-b", tag, local], capture_output=True, timeout=120)
        if len(r.stdout) > 1000:
            return vision_parts(ctx, f["ckey"], "image", jpeg(open_image(r.stdout)), f["name"], ""), None
    return [], "no embedded preview"


def ex_archive(ctx, f, local):
    e = f["ext"]; names = []; parts = []
    try:
        if zipfile.is_zipfile(local):
            z = zipfile.ZipFile(local)
            for i in z.infolist():
                n = i.filename
                if i.flag_bits & 0x800 == 0:  # not flagged UTF-8: probably cp437-mangled GBK/Shift-JIS
                    try: n = n.encode("cp437").decode("gbk")
                    except Exception: pass
                names.append(n)
                ee = ext_of(n)
                if (ee in TEXT_EXT or ee in OFFICE_EXT or ee == "pdf") and i.file_size < (20 << 20) and len(parts) < 60 and not i.is_dir():
                    tmp = local + ".member"
                    open(tmp, "wb").write(z.read(i))
                    sub = dict(f, ext=ee, name=n)
                    try:
                        # members are read locally only (text layers, office text) — no AI inside archives
                        if ee == "pdf": ps, _ = ex_pdf(NoAI(ctx), sub, tmp)
                        elif ee in OFFICE_EXT: ps, _ = ex_office(NoAI(ctx), sub, tmp)
                        else: ps, _ = ex_text(ctx, sub, tmp)
                        parts += [(n + (" " + p if p else ""), s, t) for p, s, t in ps]
                    except Exception:
                        pass
                    finally: os.remove(tmp)
        elif e in ("tar", "tgz", "gz", "bz2", "xz") and tarfile.is_tarfile(local):
            names = tarfile.open(local).getnames()
        else:
            r = subprocess.run(["7z", "l", "-slt", "-ba", local], capture_output=True, timeout=600)
            names = re.findall(r"^Path = (.+)$", decode(r.stdout), re.M)
    except Exception as ex:
        return parts, f"could not open archive: {ex}"[:200]
    if names:
        parts.insert(0, ("", "members", "\n".join(names[:5000])))
    return parts, None


class NoAI:
    """A ctx whose AI calls return nothing (used for archive members)."""
    def __init__(self, ctx): self.ctx = ctx
    def ai(self, *a, **k): return {}
    def __getattr__(self, k): return getattr(self.ctx, k)


def dhash(img):
    g = img.convert("L").resize((17, 16)); p = g.tobytes()
    return sum(1 << i for i in range(256) if p[(i // 16) * 17 + i % 16] > p[(i // 16) * 17 + i % 16 + 1])


def fmt_t(s):
    s = int(s); return f"{s // 3600:02d}:{s % 3600 // 60:02d}:{s % 60:02d}"


def probe_media(url):
    r = subprocess.run(["ffprobe", "-v", "error", "-show_entries", "format=duration:format_tags=creation_time:stream=codec_type",
                        "-of", "json", url], capture_output=True, text=True, timeout=900)
    j = json.loads(r.stdout or "{}")
    types = {s.get("codec_type") for s in j.get("streams", [])}
    fmt = j.get("format") or {}
    return float(fmt.get("duration") or 0), types, (fmt.get("tags") or {}).get("creation_time")


def ex_media(ctx, f, local_or_url, work):
    """Videos (frames + speech) and audio files (speech), read with one ffmpeg pass over HTTP."""
    dur, types, created = probe_media(local_or_url)
    parts = []
    if created: parts.append(("", "meta", f"Recorded {created}" + (f", {fmt_t(dur)} long" if dur else "")))
    video = f["kind"] == "video" and "video" in types
    has_audio = "audio" in types
    if not video and not has_audio:
        return parts, "no audio or video stream"
    # the AI steps are cached per file content; skip the (long) ffmpeg pass when both are cached
    need_frames = video and not ctx.cached(f["ckey"], "frames")
    need_audio = has_audio and not ctx.cached(f["ckey"], "speech")
    if (need_frames or need_audio) and not ctx.budget_left():
        raise NeedBudget()
    fdir = os.path.join(work, "frames"); os.makedirs(fdir, exist_ok=True)
    cmd = ["ffmpeg", "-v", "info", "-nostdin", "-y"]
    if need_frames: cmd += ["-skip_frame", "nokey"]
    cmd += ["-i", local_or_url]
    step = max(2.0, dur / 600) if dur else 2.0
    if need_frames:
        cmd += ["-map", "0:v:0", "-vf", f"select='isnan(prev_selected_t)+gte(t-prev_selected_t\\,{step})',scale='min(768,iw)':-2,showinfo",
                "-fps_mode", "vfr", "-q:v", "5", os.path.join(fdir, "f%05d.jpg")]
    if need_audio:
        cmd += ["-map", "0:a:0", "-vn", "-ac", "1", "-ar", "16000", "-b:a", "24k", "-f", "segment", "-segment_time", "600",
                os.path.join(work, "a%03d.mp3")]
    if need_frames or need_audio:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=6 * 3600)
        if r.returncode != 0 and not os.listdir(fdir) and not any(n.startswith("a") and n.endswith(".mp3") for n in os.listdir(work)):
            raise RuntimeError("ffmpeg: " + r.stderr[-300:])
        times = [float(x) for x in re.findall(r"pts_time:([0-9.]+)", r.stderr)]
    else:
        times = []
    if video:
        def frames_job():
            from PIL import Image
            files = sorted(os.listdir(fdir)); kept, last = [], None
            for i, n in enumerate(files):
                img = Image.open(os.path.join(fdir, n)); h = dhash(img)
                if last is None or bin(h ^ last).count("1") > 40:
                    kept.append((times[i] if i < len(times) else i * step, os.path.join(fdir, n))); last = h
            cap = max(4, min(MAX_FRAMES, int(4 + dur / 15)))
            if len(kept) > cap: kept = [kept[round(i * (len(kept) - 1) / (cap - 1))] for i in range(cap)]
            summary, frames, cost = {}, [], 0.0
            for s in range(0, len(kept), FRAMES_PER_CALL):
                grp = [(fmt_t(t), open(p, "rb").read()) for t, p in kept[s:s + FRAMES_PER_CALL]]
                out, c = ai.read_frames(grp, f["name"]); cost += c
                if not summary: summary = {k: out.get(k) for k in ("summary", "keywords_zh")}
                frames += [x for x in (out.get("frames") or []) if isinstance(x, dict)]
            return {**summary, "frames": frames}, cost
        r = ctx.ai(f["ckey"], "frames", frames_job)
        head = "\n".join(str(x) for x in (r.get("summary"), r.get("keywords_zh")) if x)
        if head: parts.append(("", "frames", head))
        for fr in r.get("frames") or []:
            t = "\n".join(str(x) for x in (fr.get("text"), fr.get("description")) if x)
            if t: parts.append((str(fr.get("t") or ""), "frames", t))
    if has_audio:
        def speech_job():
            segs = sorted(n for n in os.listdir(work) if n.startswith("a") and n.endswith(".mp3")); out, cost = [], 0.0
            for i, n in enumerate(segs):
                t, c = ai.transcribe(open(os.path.join(work, n), "rb").read(), "mp3", f["name"], fmt_t(i * 600)); cost += c
                if t.strip(): out.append([fmt_t(i * 600), t])
            return {"segments": out}, cost
        r = ctx.ai(f["ckey"], "speech", speech_job)
        for t, txt in r.get("segments") or []:
            parts.append((t, "speech", txt))
    return parts, None


LOCAL_KINDS = {"text": ex_text, "pdf": ex_pdf, "office": ex_office, "iwork": ex_iwork, "image": ex_image, "raw": ex_raw, "archive": ex_archive}

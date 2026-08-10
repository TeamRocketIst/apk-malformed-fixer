#!/usr/bin/env python
import argparse
import hashlib
import os
import shutil
import tempfile
import zipfile
from fix_apk import fix_apk
from fix_axml import fix_axml
from fix_asrc import fix_arsc

MAX_PATH_DEPTH = 64
MAX_MEMBER_NAME_BYTES = 1024


def _safe_extract(archive, destination):
    """Extract safely and return disk-path -> original ZIP-name mappings.

    Pathological member names are shortened only on the temporary filesystem.
    The mapping lets the repacker restore their exact archive names, which is
    required when application code opens an asset by its original name.
    """
    os.mkdir(destination)
    destination = os.path.realpath(destination)
    archive_names = {}

    for info in archive.infolist():
        original = info.filename.replace('\\', '/')
        parts = [part for part in original.split('/') if part not in ('', '.')]
        if not parts or any(part == '..' for part in parts):
            raise ValueError(f"Unsafe ZIP member path: {original!r}")

        name_bytes = len(original.encode('utf-8', 'surrogatepass'))
        if len(parts) > MAX_PATH_DEPTH or name_bytes > MAX_MEMBER_NAME_BYTES:
            digest = hashlib.sha256(
                original.encode('utf-8', 'surrogatepass')
            ).hexdigest()
            suffix = os.path.splitext(parts[-1])[1]
            if not suffix or len(suffix) > 16:
                suffix = '.bin'
            parts = ['assets', '__apkfixer_long_paths__', digest + suffix]
            print(
                f"[!] Shortened pathological ZIP path "
                f"(depth={original.count('/')}, bytes={name_bytes}) "
                f"-> {'/'.join(parts)}"
            )

        target = os.path.join(destination, *parts)
        relative_target = '/'.join(parts)
        if relative_target in archive_names and archive_names[relative_target] != original:
            raise ValueError(
                f"ZIP members collide after safe path mapping: {original!r} and "
                f"{archive_names[relative_target]!r}"
            )
        archive_names[relative_target] = original
        target_real = os.path.realpath(target)
        if os.path.commonpath((destination, target_real)) != destination:
            raise ValueError(f"ZIP member escapes extraction directory: {original!r}")

        parent = destination
        for part in parts[:-1]:
            parent = os.path.join(parent, part)
            try:
                os.mkdir(parent)
            except FileExistsError:
                if not os.path.isdir(parent):
                    raise ValueError(f"ZIP path collides with a file: {original!r}")

        if info.is_dir():
            try:
                os.mkdir(target)
            except FileExistsError:
                if not os.path.isdir(target):
                    raise ValueError(f"ZIP directory collides with a file: {original!r}")
            continue

        with archive.open(info) as source, open(target, 'wb') as output:
            shutil.copyfileobj(source, output)

    return archive_names

def fix_all(inp, outp):
    tmp = tempfile.mkdtemp(prefix="apkfix_")
    stage = os.path.join(tmp, "fixed.apk")
    ext = os.path.join(tmp, "ext")

    try:
        fix_apk(inp, stage, zipfile.ZIP_STORED)
        with zipfile.ZipFile(stage) as archive:
            archive_names = _safe_extract(archive, ext)
        for root, _, files in os.walk(ext):
            for f in files:
                p = os.path.join(root, f)

                if f == "resources.arsc":
                    try: fix_arsc(p, p)
                    except Exception as e: print(e)

                elif f.endswith(".xml"):
                    try:
                        with open(p, "rb") as fp:
                            if fp.read(2) == b'\x03\x00':
                                fix_axml(p, p)
                    except Exception as e:
                        print(e)
        print(outp, ext)
        with zipfile.ZipFile(outp, "w", zipfile.ZIP_DEFLATED) as z:
            for root, _, files in os.walk(ext):
                for f in files:
                    full = os.path.join(root, f)
                    relative = os.path.relpath(full, ext).replace(os.sep, '/')
                    z.write(full, archive_names.get(relative, relative))
        #os.system(f"zip -r {tmp}/* {outp}")
        print(f"[+] Saved -> {outp}")

    finally:
        shutil.rmtree(tmp, ignore_errors=True)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("-i", "--input", required=True)
    ap.add_argument("-o", "--output", required=True)
    a = ap.parse_args()

    fix_all(a.input, a.output)

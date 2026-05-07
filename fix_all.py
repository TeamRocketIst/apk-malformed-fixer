#!/usr/bin/env python
import os, shutil, zipfile, tempfile, argparse
from fix_apk import fix_apk
from fix_axml import fix_axml
from fix_asrc import fix_arsc

def fix_all(inp, outp):
    tmp = tempfile.mkdtemp(prefix="apkfix_")
    stage = os.path.join(tmp, "fixed.apk")
    ext = os.path.join(tmp, "ext")

    try:
        fix_apk(inp, stage, zipfile.ZIP_STORED)
        #extract_zip_raw(stage, ext)
        os.system("unzip fixed.apk -d "+ext)
        #fix_axml(ext, ext)
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
                    z.write(full, os.path.relpath(full, ext))
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
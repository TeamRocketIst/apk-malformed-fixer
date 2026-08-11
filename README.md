# apk-malformed-fixer
Fixes malformed apks, axml files and arsc 

## Installation

Run all installation commands inside a virtual environment. Do not install the
package into the system Python environment.

Install locally on Linux or macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
```

Use an editable install while developing:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

Install directly from GitHub:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install git+https://github.com/TeamRocketIst/apk-malformed-fixer.git
```

Install locally on Windows PowerShell:

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install .
```

The package has no runtime dependencies outside the Python standard library.


## Fix all

Fix everything and recreate the zip file:
```bash
$ python3 fix_all.py -i malformed.apk -o fixed.apk
```

When installed as a package, use:

```bash
apkfix -i malformed.apk -o fixed.apk
```

The installed commands are:

```bash
apkfix -i malformed.apk -o fixed.apk
apkfix-zip -i malformed.apk -o fixed.apk
apkfix-axml AndroidManifest.xml
apkfix-arsc resources.arsc
```

`fix_all.py` repairs the ZIP metadata first, then fixes forged binary XML and
resource-table fields.

## Validation

Useful checks after fixing an APK:

```bash
unzip -t fixed.apk
aapt2 dump badging fixed.apk
jadx -d jadx-output fixed.apk
unzip -p fixed.apk classes.dex > classes.dex
baksmali disassemble classes.dex -o smali
```

JADX can finish with method-level decompilation errors even when the APK,
resources, and DEX container are structurally readable. Check its log for
resource errors such as `Error decode: AndroidManifest.xml` or
`Failed to parse '.arsc' file` separately from individual method failures.

Rebuilding or changing any APK invalidates its original signature. This tool's
output is intended for analysis; sign it with an authorized key if an
installable test build is required.


## Individual fix for debugging purposes
Fix only the zip:
```bash
$ python3 fix_apk.py -i malformed.apk -o fixed.apk
$ apkfix-zip -i malformed.apk -o fixed.apk
```

Fix only the axml:
```bash
unzip fixed.apk -d out 
$ python3 fix_axml.py out
$ apkfix-axml out
```

Fix only the arsc:
```bash
unzip fixed.apk -d out 
$ python3 fix_asrc.py out/resources.arsc
$ apkfix-arsc out/resources.arsc
```

Restore back to zip:
```bash
cd out
zip -r ../out.zip *
```

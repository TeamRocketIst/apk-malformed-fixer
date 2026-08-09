# apk-malformed-fixer
Fixes malformed apks, axml files and arsc 


## Fix all

Fix everything and recreate the zip file:
```bash
$ python3 fix_all.py -i malformed.apk -o fixed.apk
```

`fix_all.py` repairs the ZIP metadata first, then fixes forged binary XML and
resource-table fields. In particular, string-pool counts are bounded by the
space available before `stringsStart`; payload bytes are not treated as an
unbounded offset array.

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
```

Fix only the axml:
```bash
unzip fixed.apk -d out 
$ python3 fix_axml.py out
```

Fix only the arsc:
```bash
unzip fixed.apk -d out 
$ python3 fix_asrc.py out/resources.arsc
```

Restore back to zip:
```bash
cd out
zip -r ../out.zip *
```

# apk-malformed-fixer
Fixes malformed apks, axml files and arsc 


## Fix all

Fix everything and recreate the zip file:
```bash
$ python3 fix_all.py -i malformed.apk -o fixed.apk
```



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


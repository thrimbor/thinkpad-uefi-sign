# thinkpad-uefi-sign
Tools to check and cryptographically sign UEFI firmware images found in ThinkPads. This will resolve the issue where your ThinkPad lets out two groups of five beeps before continuing to boot (the error indicating an invalid signature).
These tools are written in Python 3 and rely on the "pycryptodome" library. Depending on your operating system you may have packages provided for that, or have to install Python 3 manually and install pycryptodome with `pip install pycryptodome`. If you're on Windows, you can find ready-to-run binaries [here](https://github.com/thrimbor/thinkpad-uefi-sign/releases).

## Signing a modified UEFI firmware image
`./sign.py input_image.bin -o signed_image.bin`
If you're using the Windows binaries, make sure to use `sign.exe` instead.
If you see `IMAGE SIGNED!`, the signing procedure was successful.

## Veryfing the signature of a UEFI firmware image
`./verify.py signed_image.bin`
If you're using the Windows binaries, make sure to use `verify.exe` instead.
If you see `SIGNATURES CORRECT!`, the verification was successful. If you see `SIGNATURES INCORRECT!`, the signature couldn't be verified, and your image needs to get signed to not make your ThinkPad beep.

## Additional info
* The tools currently assume that, while the content of the UEFI volumes in the firmware may have changed, the volume **layout** (meaning offset in the image and size) are **unaltered**.
* The signing tool generates a throw-away key every time it signs an image. This is usually not an issue, but if, for whatever reason, you want to use a *specific* private key to sign the image, be aware that the signing tool currently does not support that.

As always, make sure that your original firmware dump is good and always have a backup!

**USE AT YOUR OWN RISK!**

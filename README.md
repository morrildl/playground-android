# Package `playground/android`

This package contains code for signing Android APKs and OTA images (notably, boot images.) It has been successfully used to sign system images for the (original) Google Pixel, in yellow mode (i.e. verified boot with locked bootloader, but using non-factory keys.)

Special thanks to Playground Global, LLC for open-sourcing this software. See `LICENSE` for details.

## Package `playground/android/apksign`

This API can sign Android APK files using both the legacy v1 signing scheme (i.e. Java `jarsigner` scheme) and the modern v2 signing scheme (which is actually a general ZIP file signing scheme.)

## Package `playground/android/otasign`

This API can sign Android system images. It can sign both bootable images and [Android verified boot images](https://source.android.com/security/verifiedboot/verified-boot). The latest versions of Android may or may not work with this code; it hasn't been recently tested.

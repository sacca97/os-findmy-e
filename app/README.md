# Android app

Android app for Find My, built on the Rust library in [`../native`](../native/README.md). Its Apple-facing flow has been verified.

## Build

Requires JDK 21 and Android SDK platform 37. The app builds for `arm64-v8a` and reads local files from `app/prebuilt/`:

- Native libraries under `jniLibs/arm64-v8a/` and the Java ADI wrapper under `java/`.
- For live debug use, the CoreADI 4.19 image at `assets/CoreADI-4.19-x86_64`.

These files are not committed. Build the native libraries using the [Rust instructions](../native/README.md), then copy them and the Java wrapper from the repository root:

```sh
mkdir -p app/prebuilt/jniLibs/arm64-v8a app/prebuilt/java/com/sacca/openfinder/adi
cp native/android/jniLibs/arm64-v8a/*.so app/prebuilt/jniLibs/arm64-v8a/
cp native/android/com/sacca/openfinder/adi/CoreAdi.java app/prebuilt/java/com/sacca/openfinder/adi/
```

```sh
cd app/android
./gradlew testDebugUnitTest
./gradlew assembleDebug
```

The APK is written to `app/android/app/build/outputs/apk/debug/app-debug.apk`. Building the APK does not contact Apple; account actions in the app do.

## CoreADI at runtime

Release builds do not bundle Apple's CoreADI. On the account screen, "Download CoreADI (external source)" fetches it from `CoreAdiDownloader.URL` and stores it only if its SHA-256 equals the pinned CoreADI 4.19 hash; "Import CoreADI file" installs one you already have. Build a signed release with `app/tools/sign_release.sh` (key kept outside the repository).

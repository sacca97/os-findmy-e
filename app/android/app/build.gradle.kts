plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

// The prebuilt native library, Java wrapper and (debug only) Apple CoreADI file / test machine live in ../../prebuilt.
val prebuilt = file("../../prebuilt")

android {
    namespace = "com.sacca.openfinder"
    compileSdk = 37

    defaultConfig {
        applicationId = "com.sacca.openfinder"
        minSdk = 26
        targetSdk = 37
        versionCode = 1
        versionName = "0.1"
        // Devices only (arm64-v8a). prebuilt/jniLibs also holds an x86_64 build; add "x86_64" here to package it.
        ndk { abiFilters += listOf("arm64-v8a") }
    }

    sourceSets {
        getByName("main") {
            jniLibs.directories.add(File(prebuilt, "jniLibs").path)     // libadi_core.so
            java.directories.add(File(prebuilt, "java").path)           // com.sacca.openfinder.adi.CoreAdi (Java)
        }
        // Git-ignored Apple binary and test machine: debug builds only, never in a release.
        getByName("debug") {
            assets.directories.add(File(prebuilt, "assets").path)
            assets.directories.add(File(prebuilt, "dev").path)
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }

    buildFeatures {
        buildConfig = true
        compose = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    implementation(platform("androidx.compose:compose-bom:2026.09.00"))
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-core")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.11.0")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.11.0")
    // Stable MapLibre Native Android SDK (OpenGL ES), used from Compose through AndroidView in ui/map/AccessoryMap.kt.
    // (MapLibre Compose 0.20.0 was tried first and dropped: GeoJSON sources that receive data after the first
    // composition never rendered. See app/README.md, "Map".)
    implementation("org.maplibre.gl:android-sdk:13.7.1")
    // Apple-side protocol is provided by the Rust library in the native/ workspace.
    implementation("com.squareup.okhttp3:okhttp:5.5.0")
    implementation("com.googlecode.plist:dd-plist:1.30")
    // CloudKit and keychain messages (app/proto/*.proto, classes pre-generated with protoc 28.3 into apple/proto).
    implementation("com.google.protobuf:protobuf-javalite:4.28.3")
    // P-224/P-256 EC, X9.63 KDF and friends, independent of what the device ships. Use the provider instance directly
    // (Android's own stripped "BC" provider must not be replaced).
    implementation("org.bouncycastle:bcprov-jdk18on:1.86")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20240303")
    testImplementation("com.squareup.okhttp3:mockwebserver3:5.5.0")   // the android.jar org.json is a stub in JVM unit tests
}

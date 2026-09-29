plugins {
    id("com.android.application")
}

android {
    namespace = "dev.phonekey.authenticator"
    compileSdk = 37

    defaultConfig {
        applicationId = "dev.phonekey.authenticator"
        // 33: KeyInfo.getSecurityLevel(), BLE permissions, GATT server notify API, notification permission.
        minSdk = 33
        targetSdk = 37
        versionCode = 5
        versionName = "0.5.0-phase5"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    sourceSets {
        // Shared protocol test vectors: the Kotlin codec must pass the same file as Python.
        getByName("test").resources.srcDir("../../protocol/test-vectors")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    implementation("androidx.appcompat:appcompat:1.8.0")
    implementation("androidx.biometric:biometric:1.1.0")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20260814") // android.jar's org.json is a stub on the JVM

    androidTestImplementation("androidx.test:runner:1.7.0")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
}

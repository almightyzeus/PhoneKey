plugins {
    id("com.android.application")
}

android {
    namespace = "dev.phonekey.authenticator"
    compileSdk = 37

    defaultConfig {
        applicationId = "dev.phonekey.authenticator"
        // 31: KeyInfo.getSecurityLevel() and the modern BLE permission model.
        minSdk = 31
        targetSdk = 37
        versionCode = 1
        versionName = "0.1.0-phase1"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
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

    androidTestImplementation("androidx.test:runner:1.7.0")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
}

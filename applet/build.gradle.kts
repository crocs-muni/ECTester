// Buildscript configuration for the javacard-gradle plugin.
// Do not modify this particular block. Dependencies for the project are lower.
buildscript {
    repositories {
        mavenCentral()
        maven("https://javacard.pro/maven")
        maven("https://deadcode.me/mvn")
    }
    dependencies {
        classpath("com.klinec:gradle-javacard:1.8.0")
    }
}

plugins {
    id("com.klinec.gradle.javacard") version "1.8.0"
    id("java")
}

// Common settings, definitions
val rootPath = rootDir.absolutePath
val libs = "$rootPath/ext/libs"
val libsSdk = "$rootPath/ext/sdks"

// Repositories for your project
repositories {
    mavenCentral()
    // mavenLocal() // for local maven repository if needed

    // Repository with JCardSim, Globalplatform, etc, ...
    maven("https://javacard.pro/maven")
    maven("https://deadcode.me/mvn")

    // Local lib repository
    flatDir {
        dirs(libs)
    }
}

// Dependencies for your project
dependencies {
    jcardsim("com.klinec:jcardsim:3.0.5.11")
    implementation("com.klinec:jcardsim:3.0.5.11")

    testImplementation(platform("org.junit:junit-bom:5.10.2"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")

    // Include plugin as it has bundled GP & other tools.
    // Alternative: include GP manually, but the included
    // version has to be compatible with the plugin.
    runtimeOnly("com.klinec:gradle-javacard:1.8.0")
}

tasks.named<Test>("test") {
    useJUnitPlatform()
}

// JavaCard SDKs and libraries
val sdks = mapOf(
        "JC211" to Triple("$libsSdk/jc211_kit", JavaVersion.VERSION_1_8, JavaVersion.VERSION_1_8),
        "JC212" to Triple("$libsSdk/jc212_kit", JavaVersion.VERSION_1_8, JavaVersion.VERSION_1_8),
        "JC221" to Triple("$libsSdk/jc221_kit", JavaVersion.VERSION_1_8, JavaVersion.VERSION_1_8),
        "JC222" to Triple("$libsSdk/jc222_kit", JavaVersion.VERSION_1_8, JavaVersion.VERSION_1_8),
        "JC303" to Triple("$libsSdk/jc303_kit", JavaVersion.VERSION_1_8, JavaVersion.VERSION_11),
        "JC304" to Triple("$libsSdk/jc304_kit", JavaVersion.VERSION_1_8, JavaVersion.VERSION_11),
        "JC305u2" to Triple("$libsSdk/jc305u2_kit", JavaVersion.VERSION_1_8, JavaVersion.VERSION_11),
        "JC305u3" to Triple("$libsSdk/jc305u3_kit", JavaVersion.VERSION_1_8, JavaVersion.VERSION_11),
        "JC305u4" to Triple("$libsSdk/jc305u4_kit", JavaVersion.VERSION_1_8, JavaVersion.VERSION_11),
        "JC310b43" to Triple("$libsSdk/jc310b43_kit", JavaVersion.VERSION_1_8, JavaVersion.VERSION_17),
        "JC310r20210706" to Triple("$libsSdk/jc310r20210706_kit", JavaVersion.VERSION_1_8, JavaVersion.VERSION_17),
        "JC320v24" to Triple("$libsSdk/jc320v24.0_kit", JavaVersion.VERSION_1_8, JavaVersion.VERSION_17),
)

var pkgAID = "4543546573746572"
var version = "0.3.3"

javacard {
    config {
        // Using custom repo with jcardsim
        debugGpPro(true)
        addImplicitJcardSim(false)
        addImplicitJcardSimJunit(false)

        if (JavaVersion.current() == JavaVersion.VERSION_1_8) {
            /*
            // Exclude for the time being, as the "excludes" param is not properly implemented upstream.
            // https://github.com/ph4r05/javacard-gradle-plugin/pull/11
            cap {
                jckit(sdks["JC221"]!!.first)
                packageName("cz.crcs.ectester.applet")
                version(version)
                aid(pkgAID)
                output("applet221.cap")

                //excludes("ECTesterAppletExtended.*")

                applet {
                    className("cz.crcs.ectester.applet.ECTesterApplet")
                    aid("454354657374657230333320323231")
                }
            }
        */

            cap {
                jckit(sdks["JC222"]!!.first)
                packageName("cz.crcs.ectester.applet")
                version(version)
                aid(pkgAID)
                output("applet222.cap")

                //excludes("ECTesterApplet.*")

                applet {
                    className("cz.crcs.ectester.applet.ECTesterAppletExtended")
                    aid("454354657374657230333320323232")
                }
            }
        }

        if (JavaVersion.current() >= JavaVersion.VERSION_1_8 && JavaVersion.current() <= JavaVersion.VERSION_11) {
            cap {
                jckit(sdks["JC305u4"]!!.first)
                packageName("cz.crcs.ectester.applet")
                version(version)
                aid(pkgAID)
                output("applet305.cap")

                //excludes("ECTesterApplet.*")

                applet {
                    className("cz.crcs.ectester.applet.ECTesterAppletExtended")
                    aid("454354657374657230333320323035")
                }
            }
        }

        if (JavaVersion.current() > JavaVersion.VERSION_11) {
            // This really only works for Java <= 17, but if the check is added, then configuration
            // of the project will not work for Java > 17.
            cap {
                jckit(sdks["JC320v24"]!!.first)
                packageName("cz.crcs.ectester.applet")
                version(version)
                aid(pkgAID)
                output("applet320.cap")

                //excludes("ECTesterApplet.*")

                applet {
                    className("cz.crcs.ectester.applet.ECTesterAppletExtended")
                    aid("454354657374657230333320323230")
                }
            }
        }
    }
}
version "0.3.3"

// Buildscript configuration for the javacard-gradle plugin.
// Do not modify this particular block. Dependencies for the project are lower.
buildscript {
    repositories {
        mavenCentral()
        maven("https://javacard.pro/maven")
        maven("https://deadcode.me/mvn")
        // mavenLocal()
    }
    dependencies {
        classpath("com.klinec:gradle-javacard:1.8.0")
    }
}

plugins {
    id("com.klinec.gradle.javacard") version "1.8.0"
    id("java")
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(8)
    }
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

    //testImplementation(group = "com.klinec", name = "javacard-tools", version = "1.0.4") {
    //    exclude group  = "com.klinec", module = "jcardsim"
    //}

    // Include plugin as it has bundled GP & other tools.
    // Alternative: include GP manually, but the included
    // version has to be compatible with the plugin.
    runtimeOnly("com.klinec:gradle-javacard:1.8.0")
}

//task dumpClassPath (dependsOn: listOf("idea")) {
//    doLast {
//        println "Gradle classpath:\n- "+configurations.implementation.files*.name.join("\n- ")
//        println "-------\n"
//        println "IDEA classpath: \n- "+file(project.name+".iml").readLines()
//        .grep(~ / . * "jar:.*/).collect { it.split("listOf(\\/)")[-3].trim() }.join("\n-")
//        println "-------\n"
//    }
//}

tasks.named<Test>("test") {
    useJUnitPlatform()
}

// JavaCard SDKs and libraries
val JC212 = libsSdk + "/jc212_kit"
val JC221 = libsSdk + "/jc221_kit"
val JC222 = libsSdk + "/jc222_kit"
val JC303 = libsSdk + "/jc303_kit"
val JC304 = libsSdk + "/jc304_kit"
val JC305 = libsSdk + "/jc305u1_kit"
val JC305u2 = libsSdk + "/jc305u2_kit"
val JC305u3 = libsSdk + "/jc305u3_kit"

// Which JavaCard SDK to use - select
// In order to compile JC222 and lower you have to have Java SDK <= 1.8
// For more info on JavaCard vs JDK version requirements inspect:
//   https://github.com/martinpaljak/ant-javacard/wiki/Version-compatibility
//
// JC310b43 supports building also for lower versions (cap.targetsdk).
// If another SDK is selected, please comment the cap.targetsdk setting.
val JC_SELECTED = JC222


javacard {

    config {
        jckit(JC_SELECTED)

        // Using custom repo with jcardsim
        debugGpPro(true)
        addImplicitJcardSim(false)
        addImplicitJcardSimJunit(false)

        cap {
            packageName("cz.crcs.ectester.applet")
            version("0.3.3")
            aid("01:ff:ff:04:05:06:07:08:09")
            output("applet.cap")

            // JC310b43 supports compilation targeting for lower API versions.
            // Here you can specify path to the SDK you want to use.
            // Only JC304 and higher are supported for targeting.
            // If JC310b43 is not used, targetsdk cannot be set.
            targetsdk(JC_SELECTED)

            // Override java bytecode version if needed.
            // javaversion "1.7"

            applet {
                className("applet.MainApplet")
                aid("01:ff:ff:04:05:06:07:08:09:01:02")
            }

            // dependencies {
            //     remote "com.klinec:globalplatform:2.1.1"
            // }
        }
    }
}
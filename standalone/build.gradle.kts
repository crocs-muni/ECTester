plugins {
    application
    jacoco
    id("com.google.osdetector") version "1.7.3"
    id("com.adarshr.test-logger") version "4.0.0"
}

repositories {
    mavenCentral()
}

dependencies {
    // Fallback to bundled wolfcrypt-jni if the submodule one is not built.
    if (file("$rootDir/ext/wolfcrypt-jni/lib/wolfcrypt-jni.jar").exists()) {
        implementation(files("$rootDir/ext/wolfcrypt-jni/lib/wolfcrypt-jni.jar"))
    } else {
        implementation(files("$rootDir/ext/wolfcrypt-jni.jar"))
    }
    implementation(project(":common"))

    testImplementation(platform("org.junit:junit-bom:5.10.2"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testImplementation("org.junit-pioneer:junit-pioneer:2.2.0")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

java {
    sourceCompatibility = JavaVersion.VERSION_11
}

application {
    applicationName = "ECTesterStandalone"
    mainClass = "cz.crcs.ectester.standalone.ECTesterStandalone"
    version = "0.3.3"
}

tasks.named<Test>("test") {
    val resultsDir = layout.buildDirectory.dir("results").get().asFile;
    doFirst {
        resultsDir.mkdirs();
    }
    ignoreFailures = true
    useJUnitPlatform()
    // Report is always generated after tests run
    finalizedBy(tasks.jacocoTestReport)

    if (JavaVersion.current() > JavaVersion.VERSION_1_8 && JavaVersion.current() < JavaVersion.VERSION_22) {
        jvmArgs("--add-exports", "jdk.crypto.ec/sun.security.ec=ALL-UNNAMED"
        )
    } else if (JavaVersion.current() >= JavaVersion.VERSION_22) {
        jvmArgs("--add-exports", "java.base/sun.security.ec=ALL-UNNAMED")
    }

    // Add wolfcrypt JNI lib path to LD_LIBRARY_PATH (as our native library loading does not handle it)
    environment(
            "LD_LIBRARY_PATH", "$rootDir/ext/wolfcrypt-jni/lib/:" + System.getenv("LD_LIBRARY_PATH")
    )
    // Add a path where we will store our test results.
    environment(
            "RESULT_PATH", resultsDir.absolutePath
    )
}

tasks.jacocoTestReport {
    reports {
        xml.required = true
    }
}

testlogger {
    theme = com.adarshr.gradle.testlogger.theme.ThemeType.MOCHA
    showStandardStreams = true
}

tasks.withType<JavaCompile> {
    if (JavaVersion.current() > JavaVersion.VERSION_1_8 && JavaVersion.current() < JavaVersion.VERSION_22) {
        options.compilerArgs.addAll(arrayOf(
                "--add-modules", "jdk.crypto.ec",
                "--add-exports", "jdk.crypto.ec/sun.security.ec=ALL-UNNAMED"
        ))
    } else if (JavaVersion.current() >= JavaVersion.VERSION_22) {
        options.compilerArgs.addAll(arrayOf(
                "--add-modules", "java.base",
                "--add-exports", "java.base/sun.security.ec=ALL-UNNAMED"
        ))
    }
}

tasks.register<Exec>("libs") {
    workingDir("src/main/resources/cz/crcs/ectester/standalone/libs/jni")
    environment("PROJECT_ROOT_PATH", rootDir.absolutePath)

    val libName = findProperty("libName") ?: ""
    if ( libName == "" ) {
        println("Building all libraries")
    } else {
        println("Buidling ${libName}")
    }

    if (osdetector.os == "windows") {
        commandLine("makefile.bat", "/c", libName)
    } else if (osdetector.os == "linux") {
        commandLine("make", "-k", "-B", libName)
    }
}

tasks.register<Jar>("uberJar") {
    archiveFileName = "ECTesterStandalone.jar"
    duplicatesStrategy = DuplicatesStrategy.WARN

    from(sourceSets.main.get().output)

    manifest {
        attributes["Main-Class"] = application.mainClass
        if (JavaVersion.current() > JavaVersion.VERSION_1_8) {
            attributes["Add-Exports"] = "jdk.crypto.ec/sun.security.ec"
        }
    }

    dependsOn(configurations.runtimeClasspath)
    from({
        configurations.runtimeClasspath.get().filter { it.name.endsWith("jar") }.map { zipTree(it).matching { exclude("META-INF/*.DSA", "META-INF/*.SF", "META-INF/*.RSA", "META-INF/versions/*/module-info.class") } }
    })
}


plugins {
    application
    id("com.google.osdetector") version "1.7.3"
}

repositories {
    mavenCentral()
}

dependencies {
    implementation(files("$rootDir/ext/wolfcrypt-jni.jar"))
    implementation(project(":common"))
}

application {
    applicationName = "ECTesterStandalone"
    mainClass = "cz.crcs.ectester.standalone.ECTesterStandalone"
    version = "0.3.3"
}

tasks.withType<JavaCompile> {
    options.compilerArgs.addAll(arrayOf(
            "--add-modules", "jdk.crypto.ec",
            "--add-exports", "jdk.crypto.ec/sun.security.ec=ALL-UNNAMED"
    ))
}

tasks.register<Exec>("libs") {
    workingDir("src/main/resources/cz/crcs/ectester/standalone/libs/jni")
    environment("PROJECT_ROOT_PATH", rootDir.absolutePath)
    if (osdetector.os == "windows") {
        commandLine("makefile.bat", "/c")
    } else if (osdetector.os == "linux"){
        commandLine("make", "-k", "-B")
    }
}

tasks.register<Jar>("uberJar") {
    archiveFileName = "ECTesterStandalone.jar"

    from(sourceSets.main.get().output)

    manifest {
        attributes["Main-Class"] = application.mainClass
    }

    dependsOn(configurations.runtimeClasspath)
    from({
        configurations.runtimeClasspath.get().filter { it.name.endsWith("jar") }.map { zipTree(it).matching { exclude("META-INF/*.DSA", "META-INF/*.SF", "META-INF/*.RSA", "META-INF/versions/*/module-info.class") } }
    })
}
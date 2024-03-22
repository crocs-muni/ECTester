plugins {
    application
}

repositories {
    mavenCentral()
}

dependencies {
    implementation(files("$rootDir/ext/wolfcrypt-jni.jar"))
    implementation(project(":common"))
}

application {
    mainClass = "cz.crcs.ectester.standalone.ECTesterStandalone"
}

tasks.withType<JavaCompile> {
    options.compilerArgs.addAll(arrayOf(
            "--add-modules", "jdk.crypto.ec",
            "--add-exports", "jdk.crypto.ec/sun.security.ec=ALL-UNNAMED"
    ))
}
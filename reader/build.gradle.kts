plugins {
    application
}

repositories {
    mavenCentral()

    // Repository with JCardSim, Globalplatform, etc, ...
    maven("https://javacard.pro/maven")
    maven("https://deadcode.me/mvn")
}

dependencies {
    implementation(project(":common"))
    implementation(project(":applet"))
}

java {
    sourceCompatibility = JavaVersion.VERSION_11
}

application {
    applicationName = "ECTesterReader"
    mainClass = "cz.crcs.ectester.reader.ECTesterReader"
    version = "0.3.3"
}

tasks.register<Jar>("uberJar") {
    archiveFileName = "ECTesterReader.jar"
    duplicatesStrategy = DuplicatesStrategy.WARN

    from(sourceSets.main.get().output)

    manifest {
        attributes["Main-Class"] = application.mainClass
    }

    dependsOn(configurations.runtimeClasspath)
    from({
        configurations.runtimeClasspath.get().filter { it.name.endsWith("jar") }.map { zipTree(it).matching { exclude("META-INF/*.DSA", "META-INF/*.SF", "META-INF/*.RSA", "META-INF/versions/*/module-info.class") } }
    })
}
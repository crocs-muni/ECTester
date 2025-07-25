plugins {
    application
    jacoco
    id("jacoco-report-aggregation")
    id("com.adarshr.test-logger") version "4.0.0"
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

    testImplementation(platform("org.junit:junit-bom:5.11.2"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testImplementation("org.junit-pioneer:junit-pioneer:2.3.0")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

java {
    sourceCompatibility = JavaVersion.VERSION_15
}

application {
    applicationName = "ECTesterReader"
    mainClass = "cz.crcs.ectester.reader.ECTesterReader"
    version = "0.3.3"
}

tasks.named<Test>("test") {
    useJUnitPlatform()
    // Report is always generated after tests run
    finalizedBy(tasks.named<JacocoReport>("testCodeCoverageReport"))
}

tasks.named<JacocoReport>("testCodeCoverageReport") {
    reports {
        html.required = true
        html.outputLocation.set(layout.buildDirectory.dir("reports/jacoco/test/html"))
        xml.required = true
        xml.outputLocation.set(layout.buildDirectory.file("reports/jacoco/test/jacocoTestReport.xml"))
    }
}

testlogger {
    theme = com.adarshr.gradle.testlogger.theme.ThemeType.MOCHA
    showStandardStreams = false
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
        configurations.runtimeClasspath.get().filter { it.name.endsWith("jar") }.map { zipTree(it).matching { exclude("META-INF/*.DSA", "META-INF/*.SF", "META-INF/*.RSA", "META-INF/versions/*/module-info.class", "apdu4j/*") } }
    })
}
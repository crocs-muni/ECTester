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

application {
    mainClass = "cz.crcs.ectester.reader.ECTesterReader"
}
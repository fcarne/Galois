/*
 * This file was generated by the Gradle 'init' task.
 */

plugins {
    id("org.galois.kotlin-application-conventions")
}

dependencies {
    val picocliVersion = "4.6.1"

    implementation(project(":core"))
    implementation("info.picocli:picocli:$picocliVersion")
}

application {
    // Define the main class for the application.
    mainClass.set("org.galois.local.GaloisTerminalKt")
}


tasks.withType<Jar> {
    // Otherwise you'll get a "No main manifest attribute" error
    manifest {
        attributes["Main-Class"] = application.mainClass.get()
    }

    // To add all of the dependencies otherwise a "NoClassDefFoundError" error
    from(sourceSets.main.get().output)

    dependsOn(configurations.runtimeClasspath)
    from({
        configurations.runtimeClasspath.get().filter { it.name.endsWith("jar") }.map { zipTree(it) }
    })
}
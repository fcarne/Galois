/*
 * This file was generated by the Gradle 'init' task.
 */

plugins {
    id("org.galois.kotlin-application-conventions")
}

dependencies {
    implementation(project(":core"))
    implementation("com.sparkjava:spark-core:2.9.3")
    implementation("com.sparkjava:spark-template-freemarker:2.7.1")

}

application {
    // Define the main class for the application.
    mainClass.set("org.galois.web.GaloisSparkKt")
}
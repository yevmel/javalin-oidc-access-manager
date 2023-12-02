plugins {
   kotlin("jvm") version "1.9.20"
}

group = "de.melnichuk.oidc"
version = "0.2.0"

repositories {
    mavenCentral()
}

dependencies {
   // web
   implementation("io.javalin:javalin:5.6.3")
   implementation("org.slf4j:slf4j-simple:2.0.7")

   // auth
   implementation("com.auth0:jwks-rsa:0.22.1")
   implementation("com.auth0:java-jwt:4.4.0")

   implementation(kotlin("stdlib"))

   testImplementation(kotlin("test"))
}

tasks.test {
    useJUnitPlatform()
}

java{
   sourceCompatibility = JavaVersion.VERSION_21
}

kotlin {
   jvmToolchain(21)
}

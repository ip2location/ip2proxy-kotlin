plugins {
    alias(libs.plugins.kotlin.jvm)
    id("com.vanniktech.maven.publish") version "0.36.0"
    id("org.jetbrains.dokka") version "2.1.0"
    `java-library`
    id("signing")
}

repositories {
    mavenCentral()
}

dependencies {
    testImplementation("org.jetbrains.kotlin:kotlin-test")
    api("com.google.code.gson:gson:2.13.2")
}

mavenPublishing {
    configureBasedOnAppliedPlugins()
    coordinates("com.ip2proxy", "ip2proxy-kotlin", "3.5.0")
    publishToMavenCentral()
    signAllPublications()

    pom {
        name.set("IP2Proxy Kotlin")
        description.set("IP2Proxy Kotlin Library can be used to find the IP addresses which are used as VPN anonymizer, open proxies, web proxies, Tor exits, data center, web hosting (DCH) range, search engine robots (SES) and residential (RES).")
        inceptionYear.set("2026")
        url.set("https://github.com/ip2location/ip2proxy-kotlin")
        licenses {
            license {
                name.set("MIT License")
                url.set("https://opensource.org/licenses/MIT")
            }
        }
        developers {
            developer {
                id.set("ip2location")
                name.set("IP2Location")
                email.set("support@ip2location.com")
            }
        }
        scm {
            connection.set("scm:git:github.com/ip2location/ip2proxy-kotlin.git")
            developerConnection.set("scm:git:ssh://github.com/ip2location/ip2proxy-kotlin.git")
            url.set("https://github.com/ip2location/ip2proxy-kotlin")
        }
    }
}

signing {
    // Call the 'gpg' command on Windows 11 so Kleopatra pops up.
    useGpgCmd()

    // This ensures we only sign when we are actually publishing
    val isPublishing = gradle.taskGraph.allTasks.any { it.name.contains("publish", ignoreCase = true) }
    setRequired(isPublishing)
}

// Apply a specific Java toolchain to ease working on different environments.
java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
}

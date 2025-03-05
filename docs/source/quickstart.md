# Quickstart

## Dependencies

This library requires IP2Proxy BIN database to function. You may download the BIN database at

-   IP2Proxy LITE BIN Data (Free): <https://lite.ip2location.com>
-   IP2Proxy Commercial BIN Data (Comprehensive):
    <https://www.ip2location.com>

## Requirements ##
Intellij IDEA: https://www.jetbrains.com/idea/

## Sample Codes

### Query geolocation information from BIN database

You can query the geolocation information from the IP2Proxy BIN database as below:

```kotlin
import kotlin.jvm.JvmStatic
import java.lang.Exception

object Main {
    @JvmStatic
    fun main(args: Array<String>) {
        try {
            val proxy = IP2Proxy()
            val all: ProxyResult
            val isProxy: Int
            val proxyType: String?
            val countryShort: String?
            val countryLong: String?
            val region: String?
            val city: String?
            val iSP: String?
            val domain: String?
            val usageType: String?
            val aSN: String?
            val `as`: String?
            val lastSeen: String?
            val threat: String?
            val provider: String?
            val fraudScore: String?
            val ip = "221.121.146.0"
            if (proxy.open("./IP2PROXY-IP-PROXYTYPE-COUNTRY-REGION-CITY-ISP-DOMAIN-USAGETYPE-ASN-LASTSEEN-THREAT-RESIDENTIAL-PROVIDER-FRAUDSCORE.BIN", IP2Proxy.IOModes.IP2PROXY_MEMORY_MAPPED) == 0) {
                println("GetModuleVersion: " + proxy.getModuleVersion())
                println("GetPackageVersion: " + proxy.getPackageVersion())
                println("GetDatabaseVersion: " + proxy.getDatabaseVersion())

                // reading all available fields
                all = proxy.getAll(ip)
                println("isProxy: " + java.lang.String.valueOf(all.isProxy))
                println("proxyType: " + all.proxyType)
                println("countryShort: " + all.countryShort)
                println("countryLong: " + all.countryLong)
                println("region: " + all.region)
                println("city: " + all.city)
                println("iSP: " + all.iSP)
                println("domain: " + all.domain)
                println("usageType: " + all.usageType)
                println("aSN: " + all.aSN)
                println("`as`: " + all.`as`)
                println("lastSeen: " + all.lastSeen)
                println("threat: " + all.threat)
                println("provider: " + all.provider)
                println("fraudScore: " + all.fraudScore)

                // reading individual fields
                isProxy = proxy.isProxy(ip)
                println("isProxy: $isProxy")
                proxyType = proxy.getProxyType(ip)
                println("proxyType: $proxyType")
                countryShort = proxy.getCountryShort(ip)
                println("countryShort: $countryShort")
                countryLong = proxy.getCountryLong(ip)
                println("countryLong: $countryLong")
                region = proxy.getRegion(ip)
                println("region: $region")
                city = proxy.getCity(ip)
                println("city: $city")
                iSP = proxy.getISP(ip)
                println("iSP: $iSP")
                domain = proxy.getDomain(ip)
                println("domain: $domain")
                usageType = proxy.getUsageType(ip)
                println("UsageType: $usageType")
                aSN = proxy.getASN(ip)
                println("aSN: $aSN")
                `as` = proxy.getAS(ip)
                println("`as`: $`as`")
                lastSeen = proxy.getLastSeen(ip)
                println("LastSeen: $lastSeen")
                threat = proxy.getThreat(ip)
                println("threat: $threat")
                provider = proxy.getProvider(ip)
                println("provider: $provider")
                fraudScore = proxy.getFraudScore(ip)
                println("fraudScore: $fraudScore")
            } else {
                println("Error reading BIN file.")
            }
            proxy.close()
        } catch (Ex: Exception) {
            println(Ex)
        }
    }
}
```

There are 2 different file modes to choose with when loading the BIN file:

1. **IOModes.IP2PROXY_FILE_IO** - File I/O reading. Slower lookup, but low resource consuming. This is the default.
2. **IOModes.IP2PROXY_MEMORY_MAPPED** - Stores whole IP2Proxy database into a memory-mapped file. Extremely resources consuming. Do not use this mode if your system do not have enough memory.
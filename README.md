# IP2Proxy Kotlin Module

This module allows user to query an IP address if it was being used as VPN anonymizer, open proxies, web proxies, Tor exits, data center, web hosting (DCH) range, search engine robots (SES) and residential (RES). It lookup the proxy IP address from **IP2Proxy BIN Data** file. This data file can be downloaded at

* Free IP2Proxy BIN Data: https://lite.ip2location.com
* Commercial IP2Proxy BIN Data: https://www.ip2location.com/database/ip2proxy

## Requirements ##
Intellij IDEA: https://www.jetbrains.com/idea/

## Methods
Below are the methods supported in this class.

|Method Name|Description|
|---|---|
|open|Open the IP2Proxy BIN data for lookup. Please see the **Usage** section of the 2 modes supported to load the BIN data file.|
|close|Close and clean up the file pointer.|
|getPackageVersion|Get the package version (1 to 11 for PX1 to PX11 respectively).|
|getModuleVersion|Get the module version.|
|getDatabaseVersion|Get the database version.|
|isProxy|Check whether if an IP address was a proxy. Returned value:<ul><li>-1 : errors</li><li>0 : not a proxy</li><li>1 : a proxy</li><li>2 : a data center IP address or search engine robot</li></ul>|
|getAll|Return the proxy information in an object.|
|getProxyType|Return the proxy type. Please visit <a href="https://www.ip2location.com/database/px10-ip-proxytype-country-region-city-isp-domain-usagetype-asn-lastseen-threat-residential" target="_blank">IP2Location</a> for the list of proxy types supported|
|getCountryShort|Return the ISO3166-1 country code (2-digits) of the proxy.|
|getCountryLong|Return the ISO3166-1 country name of the proxy.|
|getRegion|Return the ISO3166-2 region name of the proxy. Please visit <a href="https://www.ip2location.com/free/iso3166-2" target="_blank">ISO3166-2 Subdivision Code</a> for the information of ISO3166-2 supported|
|getCity|Return the city name of the proxy.|
|getISP|Return the ISP name of the proxy.|
|getDomain|Return the domain name of the proxy.|
|getUsageType|Return the usage type classification of the proxy. Please visit <a href="https://www.ip2location.com/database/px10-ip-proxytype-country-region-city-isp-domain-usagetype-asn-lastseen-threat-residential" target="_blank">IP2Location</a> for the list of usage types supported.|
|getASN|Return the autonomous system number of the proxy.|
|getAS|Return the autonomous system name of the proxy.|
|getLastSeen|Return the number of days that the proxy was last seen.|
|getThreat|Return the threat type of the proxy.|
|getProvider|Return the provider of the proxy.|

## Usage

Open and read IP2Proxy binary database. There are 2 modes:

1. **IOModes.IP2PROXY_FILE_IO** - File I/O reading. Slower lookup, but low resource consuming. This is the default.
2. **IOModes.IP2PROXY_MEMORY_MAPPED** - Stores whole IP2Proxy database into a memory-mapped file. Extremely resources consuming. Do not use this mode if your system do not have enough memory.

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
            val ip = "221.121.146.0"
            if (proxy.open("./IP2PROXY-IP-PROXYTYPE-COUNTRY-REGION-CITY-ISP-DOMAIN-USAGETYPE-ASN-LASTSEEN-THREAT-RESIDENTIAL-PROVIDER.BIN", IP2Proxy.IOModes.IP2PROXY_MEMORY_MAPPED) == 0) {
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


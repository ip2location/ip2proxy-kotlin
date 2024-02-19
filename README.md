# IP2Proxy Kotlin Module

This module allows user to query an IP address if it was being used as VPN anonymizer, open proxies, web proxies, Tor exits, data center, web hosting (DCH) range, search engine robots (SES), residential proxies (RES), consumer privacy networks (CPN), and enterprise private networks (EPN). It lookup the proxy IP address from **IP2Proxy BIN Data** file. This data file can be downloaded at

* Free IP2Proxy BIN Data: https://lite.ip2location.com
* Commercial IP2Proxy BIN Data: https://www.ip2location.com/database/ip2proxy

As an alternative, this module can also call the IP2Proxy Web Service. This requires an API key. If you don't have an existing API key, you can subscribe for one at the below:

https://www.ip2location.com/web-service/ip2proxy

## Requirements ##
Intellij IDEA: https://www.jetbrains.com/idea/

## QUERY USING THE BIN FILE

## Methods
Below are the methods supported in this module.

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

## QUERY USING THE IP2PROXY PROXY DETECTION WEB SERVICE

## Methods
Below are the methods supported in this module.

|Method Name|Description|
|---|---|
|open| Expects 3 input parameters:<ol><li>IP2Proxy API Key.</li><li>Package (PX1 - PX11)</li></li><li>Use HTTPS or HTTP</li></ol> |
|ipQuery|Query IP address. This method returns a JsonObject containing the proxy info. <ul><li>countryCode</li><li>countryName</li><li>regionName</li><li>cityName</li><li>isp</li><li>domain</li><li>usageType</li><li>asn</li><li>as</li><li>lastSeen</li><li>threat</li><li>proxyType</li><li>isProxy</li><li>provider</li><ul>|
|getCredit|This method returns the web service credit balance in a JsonObject.|

## Usage

```kotlin
import kotlin.jvm.JvmStatic
import java.lang.Exception

object Main {
    @JvmStatic
    fun main(args: Array<String>) {
        try {
            val ws = IP2ProxyWebService()

            val strIPAddress = "37.252.228.50"
            val strAPIKey = "YOUR_API_KEY"
            val strPackage = "PX11"
            val boolSSL = true

            ws.open(strAPIKey, strPackage, boolSSL)

            var myResult = ws.ipQuery(strIPAddress)

            if (myResult.get("response") != null && myResult.get("response").asString.equals("OK")) {
                println(
                    "countryCode: " + if (myResult.get("countryCode") != null) myResult.get("countryCode")
                        .asString else ""
                )
                println(
                    "countryName: " + if (myResult.get("countryName") != null) myResult.get("countryName")
                        .asString else ""
                )
                println(
                    "regionName: " + if (myResult.get("regionName") != null) myResult.get("regionName")
                        .asString else ""
                )
                println(
                    "cityName: " + if (myResult.get("cityName") != null) myResult.get("cityName").asString else ""
                )
                println("isp: " + if (myResult.get("isp") != null) myResult.get("isp").asString else "")
                println("domain: " + if (myResult.get("domain") != null) myResult.get("domain").asString else "")
                println(
                    "usageType: " + if (myResult.get("usageType") != null) myResult.get("usageType")
                        .asString else ""
                )
                println("asn: " + if (myResult.get("asn") != null) myResult.get("asn").asString else "")
                println("as: " + if (myResult.get("as") != null) myResult.get("as").asString else "")
                println(
                    "lastSeen: " + if (myResult.get("lastSeen") != null) myResult.get("lastSeen").asString else ""
                )
                println(
                    "proxyType: " + if (myResult.get("proxyType") != null) myResult.get("proxyType")
                        .asString else ""
                )
                println("threat: " + if (myResult.get("threat") != null) myResult.get("threat").asString else "")
                println(
                    "isProxy: " + if (myResult.get("isProxy") != null) myResult.get("isProxy").asString else ""
                )
                println(
                    "provider: " + if (myResult.get("provider") != null) myResult.get("provider").asString else ""
                )
            } else if (myResult.get("response") != null) {
                println("Error: " + myResult.get("response").asString);
            }

            myResult = ws.getCredit();

            if (myResult.get("response") != null) {
                println("Credit balance: " + myResult.get("response").asString);
            }
        } catch (Ex: Exception) {
            println(Ex)
        }
    }
}

```
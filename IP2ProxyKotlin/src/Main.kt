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
            if (proxy.open(
                    "./IP2PROXY-IP-PROXYTYPE-COUNTRY-REGION-CITY-ISP-DOMAIN-USAGETYPE-ASN-LASTSEEN-THREAT-RESIDENTIAL-PROVIDER.BIN",
                    IP2Proxy.IOModes.IP2PROXY_MEMORY_MAPPED
                ) == 0
            ) {
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

        println("==============================================================================")
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

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
            val ip = "221.121.146.0"
            if (proxy.open(
                    "C:/mydata/IP2PROXY-IP-PROXYTYPE-COUNTRY-REGION-CITY-ISP-DOMAIN-USAGETYPE-ASN-LASTSEEN-THREAT-RESIDENTIAL.BIN",
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
            } else {
                println("Error reading BIN file.")
            }
            proxy.close()
        } catch (Ex: Exception) {
            println(Ex)
        }
    }
}
import java.nio.MappedByteBuffer
import java.io.IOException
import java.io.RandomAccessFile
import java.nio.channels.FileChannel
import java.nio.ByteOrder
import java.math.BigInteger
import java.lang.NegativeArraySizeException
import java.lang.StringBuilder
import java.net.Inet6Address
import java.net.Inet4Address
import java.net.InetAddress
import java.net.UnknownHostException
import java.nio.ByteBuffer
import java.util.*
import java.util.regex.Pattern

class IP2Proxy {
    enum class IOModes {
        IP2PROXY_FILE_IO, IP2PROXY_MEMORY_MAPPED
    }

    enum class Modes {
        COUNTRY_SHORT, COUNTRY_LONG, REGION, CITY, ISP, PROXY_TYPE, IS_PROXY, DOMAIN, USAGE_TYPE, ASN, AS, LAST_SEEN, THREAT, PROVIDER, ALL
    }

    private var ipV4Buffer: MappedByteBuffer? = null
    private var ipV6Buffer: MappedByteBuffer? = null
    private var mapDataBuffer: MappedByteBuffer? = null
    private val indexArrayIPV4 = Array(65536) { IntArray(2) }
    private val indexArrayIPV6 = Array(65536) { IntArray(2) }
    private var ipV4Offset: Long = 0
    private var ipV6Offset: Long = 0
    private var mapDataOffset: Long = 0
    private var ipV4ColumnSize = 0
    private var ipV6ColumnSize = 0
    private var baseAddr = 0
    private var dbCount = 0
    private var dbColumn = 0
    private var dbType = 0
    private var dbDay = 1
    private var dbMonth = 1
    private var dbYear = 1
    private var baseAddrIPV6 = 0
    private var dbCountIPV6 = 0
    private var indexBaseAddr = 0
    private var indexBaseAddrIPV6 = 0
    private var productCode = 0
    // private var productType = 0
    // private var fileSize = 0
    
    private var useMemoryMappedFile = false
    private var ipDatabasePath = ""
    private var countryPositionOffset = 0
    private var regionPositionOffset = 0
    private var cityPositionOffset = 0
    private var iSPPositionOffset = 0
    private var proxyTypePositionOffset = 0
    private var domainPositionOffset = 0
    private var usageTypePositionOffset = 0
    private var aSNPositionOffset = 0
    private var asPositionOffset = 0
    private var lastSeenPositionOffset = 0
    private var threatPositionOffset = 0
    private var providerPositionOffset = 0
    private var countryEnabled = false
    private var regionEnabled = false
    private var cityEnabled = false
    private var iSPEnabled = false
    private var proxyTypeEnabled = false
    private var domainEnabled = false
    private var usageTypeEnabled = false
    private var aSNEnabled = false
    private var asEnabled = false
    private var lastSeenEnabled = false
    private var threatEnabled = false
    private var providerEnabled = false

    /**
     * This function returns the module version.
     * @return Module version
     */
    fun getModuleVersion(): String {
        return ModuleVersion
    }

    /**
     * This function returns the package version.
     * @return Package version
     */
    fun getPackageVersion(): String {
        return dbType.toString()
    }

    /**
     * This function returns the IP database version.
     * @return IP database version
     */
    fun getDatabaseVersion(): String {
        return if (dbYear == 0) {
            ""
        } else {
            "20$dbYear.$dbMonth.$dbDay"
        }
    }

    /**
     * This function returns ans integer to state if it proxy.
     * @param IP IP Address you wish to query
     * @return -1 if error, 0 if not a proxy, 1 if proxy except DCH and SES, 2 if proxy and either DCH or SES
     */
    @Throws(IOException::class)
    fun isProxy(IP: String?): Int {
        return proxyQuery(IP, Modes.IS_PROXY).isProxy
    }

    /**
     * This function returns the country code.
     * @param IP IP Address you wish to query
     * @return Country code
     */
    @Throws(IOException::class)
    fun getCountryShort(IP: String?): String? {
        return proxyQuery(IP, Modes.COUNTRY_SHORT).countryShort
    }

    /**
     * This function returns the country name.
     * @param IP IP Address you wish to query
     * @return Country name
     */
    @Throws(IOException::class)
    fun getCountryLong(IP: String?): String? {
        return proxyQuery(IP, Modes.COUNTRY_LONG).countryLong
    }

    /**
     * This function returns the region name.
     * @param IP IP Address you wish to query
     * @return region name
     */
    @Throws(IOException::class)
    fun getRegion(IP: String?): String? {
        return proxyQuery(IP, Modes.REGION).region
    }

    /**
     * This function returns the city name.
     * @param IP IP Address you wish to query
     * @return city name
     */
    @Throws(IOException::class)
    fun getCity(IP: String?): String? {
        return proxyQuery(IP, Modes.CITY).city
    }

    /**
     * This function returns the iSP name.
     * @param IP IP Address you wish to query
     * @return iSP name
     */
    @Throws(IOException::class)
    fun getISP(IP: String?): String? {
        return proxyQuery(IP, Modes.ISP).iSP
    }

    /**
     * This function returns the proxy type.
     * @param IP IP Address you wish to query
     * @return Proxy type
     */
    @Throws(IOException::class)
    fun getProxyType(IP: String?): String? {
        return proxyQuery(IP, Modes.PROXY_TYPE).proxyType
    }

    /**
     * This function returns the domain.
     * @param IP IP Address you wish to query
     * @return domain
     */
    @Throws(IOException::class)
    fun getDomain(IP: String?): String? {
        return proxyQuery(IP, Modes.DOMAIN).domain
    }

    /**
     * This function returns the usage type.
     * @param IP IP Address you wish to query
     * @return Proxy type
     */
    @Throws(IOException::class)
    fun getUsageType(IP: String?): String? {
        return proxyQuery(IP, Modes.USAGE_TYPE).usageType
    }

    /**
     * This function returns the Autonomous System Number.
     * @param IP IP Address you wish to query
     * @return Autonomous System Number
     */
    @Throws(IOException::class)
    fun getASN(IP: String?): String? {
        return proxyQuery(IP, Modes.ASN).aSN
    }

    /**
     * This function returns the Autonomous System name.
     * @param IP IP Address you wish to query
     * @return Autonomous System name
     */
    @Throws(IOException::class)
    fun getAS(IP: String?): String? {
        return proxyQuery(IP, Modes.AS).`as`
    }

    /**
     * This function returns number of days the proxy was last seen.
     * @param IP IP Address you wish to query
     * @return Number of days last seen
     */
    @Throws(IOException::class)
    fun getLastSeen(IP: String?): String? {
        return proxyQuery(IP, Modes.LAST_SEEN).lastSeen
    }

    /**
     * This function returns the threat type of the proxy.
     * @param IP IP Address you wish to query
     * @return threat type of the proxy
     */
    @Throws(IOException::class)
    fun getThreat(IP: String?): String? {
        return proxyQuery(IP, Modes.THREAT).threat
    }

    /**
     * This function returns the provider of the proxy.
     * @param IP IP Address you wish to query
     * @return provider of the proxy
     */
    @Throws(IOException::class)
    fun getProvider(IP: String?): String? {
        return proxyQuery(IP, Modes.PROVIDER).provider
    }

    /**
     * This function returns proxy result.
     * @param IP IP Address you wish to query
     * @return Proxy result
     */
    @Throws(IOException::class)
    fun getAll(IP: String?): ProxyResult {
        return proxyQuery(IP)
    }

    /**
     * This function destroys the mapped bytes.
     */
    fun close(): Int {
        destroyMappedBytes()
        baseAddr = 0
        dbCount = 0
        dbColumn = 0
        dbType = 0
        dbDay = 1
        dbMonth = 1
        dbYear = 1
        baseAddrIPV6 = 0
        dbCountIPV6 = 0
        indexBaseAddr = 0
        indexBaseAddrIPV6 = 0
        productCode = 0
        // productType = 0
        // fileSize = 0
        return 0
    }

    private fun destroyMappedBytes() {
        ipV4Buffer = null
        ipV6Buffer = null
        mapDataBuffer = null
    }

    @Throws(IOException::class)
    private fun createMappedBytes() {
        var rF: RandomAccessFile? = null
        try {
            rF = RandomAccessFile(ipDatabasePath, "r")
            val inChannel = rF.channel
            createMappedBytes(inChannel)
        } finally {
            rF?.close()
        }
    }

    @Throws(IOException::class)
    private fun createMappedBytes(inChannel: FileChannel) {
        if (ipV4Buffer == null) {
            val ipV4Bytes = ipV4ColumnSize.toLong() * dbCount.toLong()
            ipV4Offset = (baseAddr - 1).toLong()
            ipV4Buffer = inChannel.map(FileChannel.MapMode.READ_ONLY, ipV4Offset, ipV4Bytes)
            ipV4Buffer?.order(ByteOrder.LITTLE_ENDIAN)
            mapDataOffset = ipV4Offset + ipV4Bytes
        }
        if (dbCountIPV6 > 0 && ipV6Buffer == null) {
            val ipV6Bytes = ipV6ColumnSize.toLong() * dbCountIPV6.toLong()
            ipV6Offset = (baseAddrIPV6 - 1).toLong()
            ipV6Buffer = inChannel.map(FileChannel.MapMode.READ_ONLY, ipV6Offset, ipV6Bytes)
            ipV6Buffer?.order(ByteOrder.LITTLE_ENDIAN)
            mapDataOffset = ipV6Offset + ipV6Bytes
        }
        if (mapDataBuffer == null) {
            mapDataBuffer =
                    inChannel.map(FileChannel.MapMode.READ_ONLY, mapDataOffset, inChannel.size() - mapDataOffset)
            mapDataBuffer?.order(ByteOrder.LITTLE_ENDIAN)
        }
    }

    @Throws(IOException::class)
    private fun loadBIN(): Boolean {
        var loadOK = false
        var rF: RandomAccessFile? = null
        try {
            if (ipDatabasePath.isNotEmpty()) {
                rF = RandomAccessFile(ipDatabasePath, "r")
                val inChannel = rF.channel
                val headerBuffer = inChannel.map(FileChannel.MapMode.READ_ONLY, 0, 64) // 64 bytes header
                headerBuffer.order(ByteOrder.LITTLE_ENDIAN)
                dbType = headerBuffer[0].toInt()
                dbColumn = headerBuffer[1].toInt()
                dbYear = headerBuffer[2].toInt()
                dbMonth = headerBuffer[3].toInt()
                dbDay = headerBuffer[4].toInt()
                dbCount = headerBuffer.getInt(5) // 4 bytes
                baseAddr = headerBuffer.getInt(9) // 4 bytes
                dbCountIPV6 = headerBuffer.getInt(13) // 4 bytes
                baseAddrIPV6 = headerBuffer.getInt(17) // 4 bytes
                indexBaseAddr = headerBuffer.getInt(21) //4 bytes
                indexBaseAddrIPV6 = headerBuffer.getInt(25) //4 bytes
                productCode = headerBuffer[29].toInt()
                // productType = headerBuffer[30].toInt()
                // fileSize = headerBuffer.getInt(31) //4 bytes

                // check if is correct BIN (should be 2 for IP2Proxy BIN file), also checking for zipped file (PK being the first 2 chars)
                if ((productCode != 2 && dbYear >= 21) || (dbType == 80 && dbColumn == 75)) { // only BINs from Jan 2021 onwards have this byte set
                    throw IOException("Incorrect IP2Proxy BIN file format. Please make sure that you are using the latest IP2Proxy BIN file.")
                }

                ipV4ColumnSize = dbColumn shl 2 // 4 bytes each column
                ipV6ColumnSize =
                        16 + (dbColumn - 1 shl 2) // 4 bytes each column, except IPFrom column which is 16 bytes

                countryPositionOffset = if (COUNTRY_POSITION[dbType] != 0) COUNTRY_POSITION[dbType] - 2 shl 2 else 0
                regionPositionOffset = if (REGION_POSITION[dbType] != 0) REGION_POSITION[dbType] - 2 shl 2 else 0
                cityPositionOffset = if (CITY_POSITION[dbType] != 0) CITY_POSITION[dbType] - 2 shl 2 else 0
                iSPPositionOffset = if (ISP_POSITION[dbType] != 0) ISP_POSITION[dbType] - 2 shl 2 else 0
                proxyTypePositionOffset =
                        if (PROXYTYPE_POSITION[dbType] != 0) PROXYTYPE_POSITION[dbType] - 2 shl 2 else 0
                domainPositionOffset = if (DOMAIN_POSITION[dbType] != 0) DOMAIN_POSITION[dbType] - 2 shl 2 else 0
                usageTypePositionOffset =
                        if (USAGETYPE_POSITION[dbType] != 0) USAGETYPE_POSITION[dbType] - 2 shl 2 else 0
                aSNPositionOffset = if (ASN_POSITION[dbType] != 0) ASN_POSITION[dbType] - 2 shl 2 else 0
                asPositionOffset = if (AS_POSITION[dbType] != 0) AS_POSITION[dbType] - 2 shl 2 else 0
                lastSeenPositionOffset = if (LASTSEEN_POSITION[dbType] != 0) LASTSEEN_POSITION[dbType] - 2 shl 2 else 0
                threatPositionOffset = if (THREAT_POSITION[dbType] != 0) THREAT_POSITION[dbType] - 2 shl 2 else 0
                providerPositionOffset = if (PROVIDER_POSITION[dbType] != 0) PROVIDER_POSITION[dbType] - 2 shl 2 else 0
                countryEnabled = COUNTRY_POSITION[dbType] != 0
                regionEnabled = REGION_POSITION[dbType] != 0
                cityEnabled = CITY_POSITION[dbType] != 0
                iSPEnabled = ISP_POSITION[dbType] != 0
                proxyTypeEnabled = PROXYTYPE_POSITION[dbType] != 0
                domainEnabled = DOMAIN_POSITION[dbType] != 0
                usageTypeEnabled = USAGETYPE_POSITION[dbType] != 0
                aSNEnabled = ASN_POSITION[dbType] != 0
                asEnabled = AS_POSITION[dbType] != 0
                lastSeenEnabled = LASTSEEN_POSITION[dbType] != 0
                threatEnabled = THREAT_POSITION[dbType] != 0
                providerEnabled = PROVIDER_POSITION[dbType] != 0
                val indexBuffer = inChannel.map(
                        FileChannel.MapMode.READ_ONLY,
                        (indexBaseAddr - 1).toLong(),
                        (baseAddr - indexBaseAddr).toLong()
                )
                indexBuffer.order(ByteOrder.LITTLE_ENDIAN)
                var pointer = 0

                // read IPv4 index
                for (x in indexArrayIPV4.indices) {
                    indexArrayIPV4[x][0] = indexBuffer.getInt(pointer) // 4 bytes for from row
                    indexArrayIPV4[x][1] = indexBuffer.getInt(pointer + 4) // 4 bytes for to row
                    pointer += 8
                }
                if (indexBaseAddrIPV6 > 0) {
                    // read IPv6 index
                    for (x in indexArrayIPV6.indices) {
                        indexArrayIPV6[x][0] = indexBuffer.getInt(pointer) // 4 bytes for from row
                        indexArrayIPV6[x][1] = indexBuffer.getInt(pointer + 4) // 4 bytes for to row
                        pointer += 8
                    }
                }
                if (useMemoryMappedFile) {
                    createMappedBytes(inChannel)
                } else {
                    destroyMappedBytes()
                }
                loadOK = true
            }
        } finally {
            rF?.close()
        }
        return loadOK
    }

    /**
     * This function initialize the component with the BIN file path and IO mode.
     * @param DatabasePath Path to the BIN database file
     * @param IOMode Default is file IO
     * @return -1 if encounter error else 0
     */
    @JvmOverloads
    @Throws(IOException::class)
    fun open(DatabasePath: String, IOMode: IOModes = IOModes.IP2PROXY_FILE_IO): Int {
        return if (dbType == 0) {
            ipDatabasePath = DatabasePath
            if (IOMode == IOModes.IP2PROXY_MEMORY_MAPPED) {
                useMemoryMappedFile = true
            }
            if (!loadBIN()) {
                -1
            } else {
                0
            }
        } else {
            0
        }
    }

    /**
     * This function to query IP2Proxy data.
     * @param IPAddress IP Address you wish to query
     * @return IP2Proxy data
     */
    @Throws(IOException::class)
    fun proxyQuery(IPAddress: String?): ProxyResult {
        return proxyQuery(IPAddress, Modes.ALL)
    }

    @Throws(IOException::class)
    fun proxyQuery(IPAddress: String?, Mode: Modes): ProxyResult {
        val ipAddress = IPAddress?.trim { it <= ' ' } ?: "" // if null, it becomes empty string
        val result = ProxyResult()
        var rF: RandomAccessFile? = null
        var buf: ByteBuffer? = null
        var dataBuf: ByteBuffer? = null
        return try {
            if (ipAddress.isEmpty()) {
                result.isProxy = -1
                result.proxyType = MSG_INVALID_IP
                result.countryShort = MSG_INVALID_IP
                result.countryLong = MSG_INVALID_IP
                result.region = MSG_INVALID_IP
                result.city = MSG_INVALID_IP
                result.iSP = MSG_INVALID_IP
                result.domain = MSG_INVALID_IP
                result.usageType = MSG_INVALID_IP
                result.aSN = MSG_INVALID_IP
                result.`as` = MSG_INVALID_IP
                result.lastSeen = MSG_INVALID_IP
                result.threat = MSG_INVALID_IP
                result.provider = MSG_INVALID_IP
                return result
            }
            var ipNo: BigInteger
            val indexAddr: Int
            val actualIPType: Int
            var ipType: Int
            var baseAddr = 0
            val columnSize: Int
            var bufCapacity = 0
            val maxIPRange: BigInteger
            var rowOffset: Long
            var rowOffset2: Long
            val bI: Array<BigInteger>
            var overCapacity = false
            val retArr: Array<String>
            try {
                bI = ip2No(ipAddress)
                ipType = bI[0].toInt()
                ipNo = bI[1]
                actualIPType = bI[2].toInt()
                if (actualIPType == 6) {
                    retArr = expandIPV6(ipAddress, ipType)
                    ipType = retArr[1].toInt()
                }
            } catch (ex: UnknownHostException) {
                result.isProxy = -1
                result.proxyType = MSG_INVALID_IP
                result.countryShort = MSG_INVALID_IP
                result.countryLong = MSG_INVALID_IP
                result.region = MSG_INVALID_IP
                result.city = MSG_INVALID_IP
                result.iSP = MSG_INVALID_IP
                result.domain = MSG_INVALID_IP
                result.usageType = MSG_INVALID_IP
                result.aSN = MSG_INVALID_IP
                result.`as` = MSG_INVALID_IP
                result.lastSeen = MSG_INVALID_IP
                result.threat = MSG_INVALID_IP
                result.provider = MSG_INVALID_IP
                return result
            }
            var pos: Long = 0
            var low: Long = 0
            var high: Long
            var mid: Long
            var ipFrom: BigInteger
            var ipTo: BigInteger

            // Read BIN if haven't done so
            if (dbType == 0) {
                if (!loadBIN()) { // problems reading BIN
                    result.isProxy = -1
                    result.proxyType = MSG_MISSING_FILE
                    result.countryShort = MSG_MISSING_FILE
                    result.countryLong = MSG_MISSING_FILE
                    result.region = MSG_MISSING_FILE
                    result.city = MSG_MISSING_FILE
                    result.iSP = MSG_MISSING_FILE
                    result.domain = MSG_MISSING_FILE
                    result.usageType = MSG_MISSING_FILE
                    result.aSN = MSG_MISSING_FILE
                    result.`as` = MSG_MISSING_FILE
                    result.lastSeen = MSG_MISSING_FILE
                    result.threat = MSG_MISSING_FILE
                    result.provider = MSG_MISSING_FILE
                    return result
                }
            }
            if (useMemoryMappedFile) {
                if (ipV4Buffer == null || dbCountIPV6 > 0 && ipV6Buffer == null || mapDataBuffer == null) {
                    createMappedBytes()
                }
            } else {
                destroyMappedBytes()
                rF = RandomAccessFile(ipDatabasePath, "r")
            }
            if (ipType == 4) { // IPv4
                maxIPRange = MAX_IPV4_RANGE
                if (useMemoryMappedFile) {
                    buf =
                            ipV4Buffer!!.duplicate() // this enables this thread to maintain its own position in a multi-threaded environment
                    buf.order(ByteOrder.LITTLE_ENDIAN)
                    bufCapacity = buf.capacity()
                } else {
                    baseAddr = this.baseAddr
                }
                columnSize = ipV4ColumnSize
                indexAddr = ipNo.shiftRight(16).toInt()
                low = indexArrayIPV4[indexAddr][0].toLong()
                high = indexArrayIPV4[indexAddr][1].toLong()
            } else { // IPv6
                if (dbCountIPV6 == 0) {
                    result.isProxy = -1
                    result.proxyType = MSG_IPV6_UNSUPPORTED
                    result.countryShort = MSG_IPV6_UNSUPPORTED
                    result.countryLong = MSG_IPV6_UNSUPPORTED
                    result.region = MSG_IPV6_UNSUPPORTED
                    result.city = MSG_IPV6_UNSUPPORTED
                    result.iSP = MSG_IPV6_UNSUPPORTED
                    result.domain = MSG_IPV6_UNSUPPORTED
                    result.usageType = MSG_IPV6_UNSUPPORTED
                    result.aSN = MSG_IPV6_UNSUPPORTED
                    result.`as` = MSG_IPV6_UNSUPPORTED
                    result.lastSeen = MSG_IPV6_UNSUPPORTED
                    result.threat = MSG_IPV6_UNSUPPORTED
                    result.provider = MSG_IPV6_UNSUPPORTED
                    return result
                }
                maxIPRange = MAX_IPV6_RANGE
                high = dbCountIPV6.toLong()
                if (useMemoryMappedFile) {
                    buf =
                            ipV6Buffer!!.duplicate() // this enables this thread to maintain its own position in a multi-threaded environment
                    buf.order(ByteOrder.LITTLE_ENDIAN)
                    bufCapacity = buf.capacity()
                } else {
                    baseAddr = baseAddrIPV6
                }
                columnSize = ipV6ColumnSize
                if (indexBaseAddrIPV6 > 0) {
                    indexAddr = ipNo.shiftRight(112).toInt()
                    low = indexArrayIPV6[indexAddr][0].toLong()
                    high = indexArrayIPV6[indexAddr][1].toLong()
                }
            }
            if (ipNo.compareTo(maxIPRange) == 0) ipNo = ipNo.subtract(BigInteger.ONE)
            while (low <= high) {
                mid = ((low + high) / 2)
                rowOffset = baseAddr + mid * columnSize
                rowOffset2 = rowOffset + columnSize
                if (useMemoryMappedFile) {
                    overCapacity = rowOffset2 >= bufCapacity
                }
                ipFrom = read32Or128(rowOffset, ipType, buf, rF)
                ipTo = if (overCapacity) BigInteger.ZERO else read32Or128(rowOffset2, ipType, buf, rF)
                if (ipNo >= ipFrom && ipNo < ipTo) {
                    val isProxy: Int
                    var proxyType: String? = MSG_NOT_SUPPORTED
                    var countryShort: String? = MSG_NOT_SUPPORTED
                    var countryLong: String? = MSG_NOT_SUPPORTED
                    var region: String? = MSG_NOT_SUPPORTED
                    var city: String? = MSG_NOT_SUPPORTED
                    var iSP: String? = MSG_NOT_SUPPORTED
                    var domain: String? = MSG_NOT_SUPPORTED
                    var usageType: String? = MSG_NOT_SUPPORTED
                    var aSN: String? = MSG_NOT_SUPPORTED
                    var `as`: String? = MSG_NOT_SUPPORTED
                    var lastSeen: String? = MSG_NOT_SUPPORTED
                    var threat: String? = MSG_NOT_SUPPORTED
                    var provider: String? = MSG_NOT_SUPPORTED
                    var firstCol = 4 // IP From is 4 bytes
                    if (ipType == 6) { // IPv6
                        firstCol = 16 // IPv6 is 16 bytes
                    }

                    // read the row here after the IP From column (remaining columns are all 4 bytes)
                    val rowLen = columnSize - firstCol
                    val row: ByteArray = readRow(rowOffset + firstCol, rowLen.toLong(), buf, rF)
                    if (useMemoryMappedFile) {
                        dataBuf =
                                mapDataBuffer!!.duplicate() // this is to enable reading of a range of bytes in multi-threaded environment
                        dataBuf.order(ByteOrder.LITTLE_ENDIAN)
                    }
                    if (proxyTypeEnabled) {
                        if (Mode == Modes.ALL || Mode == Modes.PROXY_TYPE || Mode == Modes.IS_PROXY) {
                            proxyType = readStr(read32Row(row, proxyTypePositionOffset).toLong(), dataBuf, rF)
                        }
                    }
                    if (countryEnabled) {
                        if (Mode == Modes.ALL || Mode == Modes.COUNTRY_SHORT || Mode == Modes.COUNTRY_LONG || Mode == Modes.IS_PROXY) {
                            pos = read32Row(row, countryPositionOffset).toLong()
                        }
                        if (Mode == Modes.ALL || Mode == Modes.COUNTRY_SHORT || Mode == Modes.IS_PROXY) {
                            countryShort = readStr(pos, dataBuf, rF)
                        }
                        if (Mode == Modes.ALL || Mode == Modes.COUNTRY_LONG) {
                            countryLong = readStr(pos + 3, dataBuf, rF)
                        }
                    }
                    if (regionEnabled) {
                        if (Mode == Modes.ALL || Mode == Modes.REGION) {
                            region = readStr(read32Row(row, regionPositionOffset).toLong(), dataBuf, rF)
                        }
                    }
                    if (cityEnabled) {
                        if (Mode == Modes.ALL || Mode == Modes.CITY) {
                            city = readStr(read32Row(row, cityPositionOffset).toLong(), dataBuf, rF)
                        }
                    }
                    if (iSPEnabled) {
                        if (Mode == Modes.ALL || Mode == Modes.ISP) {
                            iSP = readStr(read32Row(row, iSPPositionOffset).toLong(), dataBuf, rF)
                        }
                    }
                    if (domainEnabled) {
                        if (Mode == Modes.ALL || Mode == Modes.DOMAIN) {
                            domain = readStr(read32Row(row, domainPositionOffset).toLong(), dataBuf, rF)
                        }
                    }
                    if (usageTypeEnabled) {
                        if (Mode == Modes.ALL || Mode == Modes.USAGE_TYPE) {
                            usageType = readStr(read32Row(row, usageTypePositionOffset).toLong(), dataBuf, rF)
                        }
                    }
                    if (aSNEnabled) {
                        if (Mode == Modes.ALL || Mode == Modes.ASN) {
                            aSN = readStr(read32Row(row, aSNPositionOffset).toLong(), dataBuf, rF)
                        }
                    }
                    if (asEnabled) {
                        if (Mode == Modes.ALL || Mode == Modes.AS) {
                            `as` = readStr(read32Row(row, asPositionOffset).toLong(), dataBuf, rF)
                        }
                    }
                    if (lastSeenEnabled) {
                        if (Mode == Modes.ALL || Mode == Modes.LAST_SEEN) {
                            lastSeen = readStr(read32Row(row, lastSeenPositionOffset).toLong(), dataBuf, rF)
                        }
                    }
                    if (threatEnabled) {
                        if (Mode == Modes.ALL || Mode == Modes.THREAT) {
                            threat = readStr(read32Row(row, threatPositionOffset).toLong(), dataBuf, rF)
                        }
                    }
                    if (providerEnabled) {
                        if (Mode == Modes.ALL || Mode == Modes.PROVIDER) {
                            provider = readStr(read32Row(row, providerPositionOffset).toLong(), dataBuf, rF)
                        }
                    }
                    isProxy = if (countryShort == "-" || proxyType == "-") {
                        0
                    } else {
                        if (proxyType == "DCH" || proxyType == "SES") {
                            2
                        } else {
                            1
                        }
                    }
                    result.isProxy = isProxy
                    result.proxyType = proxyType
                    result.countryShort = countryShort
                    result.countryLong = countryLong
                    result.region = region
                    result.city = city
                    result.iSP = iSP
                    result.domain = domain
                    result.usageType = usageType
                    result.aSN = aSN
                    result.`as` = `as`
                    result.lastSeen = lastSeen
                    result.threat = threat
                    result.provider = provider
                    return result
                } else {
                    if (ipNo < ipFrom) {
                        high = mid - 1
                    } else {
                        low = mid + 1
                    }
                }
            }
            result.isProxy = -1
            result.proxyType = MSG_INVALID_IP
            result.countryShort = MSG_INVALID_IP
            result.countryLong = MSG_INVALID_IP
            result.region = MSG_INVALID_IP
            result.city = MSG_INVALID_IP
            result.iSP = MSG_INVALID_IP
            result.domain = MSG_INVALID_IP
            result.usageType = MSG_INVALID_IP
            result.aSN = MSG_INVALID_IP
            result.`as` = MSG_INVALID_IP
            result.lastSeen = MSG_INVALID_IP
            result.threat = MSG_INVALID_IP
            result.provider = MSG_INVALID_IP
            result
        } finally {
            rF?.close()
        }
    }

    private fun expandIPV6(IP: String, IPType: Int): Array<String> {
        val tmp = "0000:0000:0000:0000:0000:"
        val padMe = "0000"
        val hexOffset: Long = 0xFF
        var ip2 = IP.uppercase(Locale.getDefault())
        var retType = IPType.toString()
        if (IPType == 4) {
            if (Pattern4.matcher(ip2).matches()) {
                ip2 = ip2.replace("::".toRegex(), tmp)
            } else {
                val mat = Pattern5.matcher(ip2)
                if (mat.matches()) {
                    val match = mat.group(1)
                    val arr =
                            match.replace("^:+".toRegex(), "").replace(":+$".toRegex(), "").split(":".toRegex())
                                    .toTypedArray()
                    val len = arr.size
                    val bf = StringBuilder(32)
                    for (x in 0 until len) {
                        val unpadded = arr[x]
                        bf.append(padMe.substring(unpadded.length) + unpadded)
                    }
                    var tmp2 = BigInteger(bf.toString(), 16).toLong()
                    val bytes =
                            longArrayOf(0, 0, 0, 0) // using long in place of bytes due to 2's complement signed issue
                    for (x in 0..3) {
                        bytes[x] = tmp2 and hexOffset
                        tmp2 = tmp2 shr 8
                    }
                    ip2 = ip2.replace(
                            match + "$".toRegex(),
                            ":" + bytes[3] + "." + bytes[2] + "." + bytes[1] + "." + bytes[0]
                    )
                    ip2 = ip2.replace("::".toRegex(), tmp)
                }
            }
        } else if (IPType == 6) {
            if (ip2 == "::") {
                ip2 += "0.0.0.0"
                ip2 = ip2.replace("::".toRegex(), tmp + "FFFF:")
                retType = "4"
            } else {
                val mat = Pattern4.matcher(ip2)
                if (mat.matches()) {
                    val v6Part = mat.group(1)
                    val v4Part = mat.group(2)
                    val v4Arr = v4Part.split("\\.".toRegex()).toTypedArray()
                    val v4IntArr = IntArray(4)
                    var len = v4IntArr.size
                    for (x in 0 until len) {
                        v4IntArr[x] = v4Arr[x].toInt()
                    }
                    val part1 = (v4IntArr[0] shl 8) + v4IntArr[1]
                    val part2 = (v4IntArr[2] shl 8) + v4IntArr[3]
                    val part1Hex = Integer.toHexString(part1)
                    val part2Hex = Integer.toHexString(part2)
                    val bf = StringBuilder(v6Part.length + 9)
                    bf.append(v6Part)
                    bf.append(padMe.substring(part1Hex.length))
                    bf.append(part1Hex)
                    bf.append(":")
                    bf.append(padMe.substring(part2Hex.length))
                    bf.append(part2Hex)
                    ip2 = bf.toString().toUpperCase()
                    val arr = ip2.split("::".toRegex()).toTypedArray()
                    val leftSide = arr[0].split(":".toRegex()).toTypedArray()
                    val bf2 = StringBuilder(40)
                    val bf3 = StringBuilder(40)
                    val bf4 = StringBuilder(40)
                    len = leftSide.size
                    var totalSegments = 0
                    for (x in 0 until len) {
                        if (leftSide[x].isNotEmpty()) {
                            totalSegments++
                            bf2.append(padMe.substring(leftSide[x].length))
                            bf2.append(leftSide[x])
                            bf2.append(":")
                        }
                    }
                    if (arr.size > 1) {
                        val rightSide = arr[1].split(":".toRegex()).toTypedArray()
                        len = rightSide.size
                        for (x in 0 until len) {
                            if (rightSide[x].isNotEmpty()) {
                                totalSegments++
                                bf3.append(padMe.substring(rightSide[x].length))
                                bf3.append(rightSide[x])
                                bf3.append(":")
                            }
                        }
                    }
                    val totalSegmentsLeft = 8 - totalSegments
                    if (totalSegmentsLeft == 6) {
                        for (x in 1 until totalSegmentsLeft) {
                            bf4.append(padMe)
                            bf4.append(":")
                        }
                        bf4.append("FFFF:")
                        bf4.append(v4Part)
                        retType = "4"
                        ip2 = bf4.toString()
                    } else {
                        for (x in 0 until totalSegmentsLeft) {
                            bf4.append(padMe)
                            bf4.append(":")
                        }
                        bf2.append(bf4).append(bf3)
                        ip2 = bf2.toString().replace(":$".toRegex(), "")
                    }
                } else {
                    val mat2 = Pattern6.matcher(ip2)
                    if (mat2.matches()) {
                        val match = mat2.group(1)
                        val arr =
                                match.replace("^:+".toRegex(), "").replace(":+$".toRegex(), "").split(":".toRegex())
                                        .toTypedArray()
                        val len = arr.size
                        val bf = StringBuilder(32)
                        for (x in 0 until len) {
                            val unpadded = arr[x]
                            bf.append(padMe.substring(unpadded.length) + unpadded)
                        }
                        var tmp2 = BigInteger(bf.toString(), 16).toLong()
                        val bytes = longArrayOf(
                                0,
                                0,
                                0,
                                0
                        ) // using long in place of bytes due to 2's complement signed issue
                        for (x in 0..3) {
                            bytes[x] = tmp2 and hexOffset
                            tmp2 = tmp2 shr 8
                        }
                        ip2 = ip2.replace(
                                match + "$".toRegex(),
                                ":" + bytes[3] + "." + bytes[2] + "." + bytes[1] + "." + bytes[0]
                        )
                        ip2 = ip2.replace("::".toRegex(), tmp + "FFFF:")
                        retType = "4"
                    } else {
                        val arr = ip2.split("::".toRegex()).toTypedArray()
                        val leftSide = arr[0].split(":".toRegex()).toTypedArray()
                        val bf2 = StringBuilder(40)
                        val bf3 = StringBuilder(40)
                        val bf4 = StringBuilder(40)
                        var len = leftSide.size
                        var totalSegments = 0
                        for (x in 0 until len) {
                            if (leftSide[x].isNotEmpty()) {
                                totalSegments++
                                bf2.append(padMe.substring(leftSide[x].length))
                                bf2.append(leftSide[x])
                                bf2.append(":")
                            }
                        }
                        if (arr.size > 1) {
                            val rightSide =
                                    arr[1].split(":".toRegex()).toTypedArray()
                            len = rightSide.size
                            for (x in 0 until len) {
                                if (rightSide[x].isNotEmpty()) {
                                    totalSegments++
                                    bf3.append(padMe.substring(rightSide[x].length))
                                    bf3.append(rightSide[x])
                                    bf3.append(":")
                                }
                            }
                        }
                        val totalSegmentsLeft = 8 - totalSegments
                        for (x in 0 until totalSegmentsLeft) {
                            bf4.append(padMe)
                            bf4.append(":")
                        }
                        bf2.append(bf4).append(bf3)
                        ip2 = bf2.toString().replace(":$".toRegex(), "")
                    }
                }
            }
        }
        return arrayOf(ip2, retType)
    }

    private fun reverse(arr: ByteArray?) {
        if (arr == null) {
            return
        }
        var i = 0
        var j = arr.size - 1
        var tmp: Byte
        while (j > i) {
            tmp = arr[j]
            arr[j] = arr[i]
            arr[i] = tmp
            j--
            i++
        }
    }

    @Throws(IOException::class)
    private fun readRow(Position: Long, myLen: Long, buf: ByteBuffer?, rH: RandomAccessFile?): ByteArray {
        val row = ByteArray(myLen.toInt())
        if (useMemoryMappedFile) {
            buf!!.position(Position.toInt())
            buf[row, 0, myLen.toInt()]
        } else {
            rH!!.seek(Position - 1)
            rH.read(row, 0, myLen.toInt())
        }
        return row
    }

    @Throws(IOException::class)
    private fun read32Or128(position: Long, ipType: Int, buf: ByteBuffer?, rH: RandomAccessFile?): BigInteger {
        if (ipType == 4) {
            return read32(position, buf, rH)
        } else if (ipType == 6) {
            return read128(position, buf, rH)
        }
        return BigInteger.ZERO
    }

    @Throws(IOException::class)
    private fun read128(Position: Long, buf: ByteBuffer?, rH: RandomAccessFile?): BigInteger {
        val retVal: BigInteger
        val bSize = 16
        val bytes = ByteArray(bSize)
        if (useMemoryMappedFile) {
            buf!!.position(Position.toInt())
            buf[bytes, 0, bSize]
        } else {
            rH!!.seek(Position - 1)
            rH.read(bytes, 0, bSize)
        }
        reverse(bytes)
        retVal = BigInteger(1, bytes)
        return retVal
    }

    @Throws(IOException::class)
    private fun read32Row(row: ByteArray, from: Int): BigInteger {
        val len = 4 // 4 bytes
        val bytes = ByteArray(len)
        System.arraycopy(row, from, bytes, 0, len)
        reverse(bytes)
        return BigInteger(1, bytes)
    }

    @Throws(IOException::class)
    private fun read32(position: Long, buf: ByteBuffer?, rH: RandomAccessFile?): BigInteger {
        return if (useMemoryMappedFile) {
            // simulate unsigned int by using long
            BigInteger.valueOf(
                    buf!!.getInt(position.toInt()).toLong() and 0xffffffffL
            ) // use absolute offset to be thread-safe
        } else {
            val bSize = 4
            rH!!.seek(position - 1)
            val bytes = ByteArray(bSize)
            rH.read(bytes, 0, bSize)
            reverse(bytes)
            BigInteger(1, bytes)
        }
    }

    @Throws(IOException::class)
    private fun readStr(position: Long, buf: ByteBuffer?, rH: RandomAccessFile?): String? {
        var pos = position
        val size: Int

        val bytes: ByteArray?
        if (useMemoryMappedFile) {
            pos -= mapDataOffset // position stored in BIN file is for full file, not just the mapped data segment, so need to minus
            size = mapDataBuffer!![pos.toInt()].toInt() // use absolute offset to be thread-safe
            try {
                bytes = ByteArray(size)
                buf!!.position(pos.toInt() + 1)
                buf[bytes, 0, size]
            } catch (e: NegativeArraySizeException) {
                return null
            }
        } else {
            rH!!.seek(position)
            size = rH.read()
            try {
                bytes = ByteArray(size)
                rH.read(bytes, 0, size)
            } catch (e: NegativeArraySizeException) {
                return null
            }
        }
        return String(bytes)
    }

    @Throws(UnknownHostException::class)
    private fun ip2No(IP: String): Array<BigInteger> {
        val a1: BigInteger
        var a2: BigInteger
        var a3 = BigInteger("4")
        if (Pattern1.matcher(IP).matches()) { // should be IPv4
            a1 = BigInteger("4")
            a2 = BigInteger(ipV4No(IP).toString())
        } else if (Pattern2.matcher(IP).matches() || Pattern3.matcher(IP)
                        .matches() || Pattern7.matcher(IP).matches()
        ) {
            throw UnknownHostException()
        } else {
            a3 = BigInteger("6")
            val ia = InetAddress.getByName(IP)
            val bytes = ia.address
            var ipType = "0" // BigInteger needs String in the constructor
            if (ia is Inet6Address) {
                ipType = "6"
            } else if (ia is Inet4Address) { // this will run in cases of IPv4-mapped IPv6 addresses
                ipType = "4"
            }
            a2 = BigInteger(1, bytes)
            if (a2 in FROM_6TO4..TO_6TO4) {
                // 6to4 so need to remap to ipv4
                ipType = "4"
                a2 = a2.shiftRight(80)
                a2 = a2.and(LAST_32BITS)
                a3 = BigInteger("4")
            } else if (a2 in FROM_TEREDO..TO_TEREDO) {
                // Teredo so need to remap to ipv4
                ipType = "4"
                a2 = a2.not()
                a2 = a2.and(LAST_32BITS)
                a3 = BigInteger("4")
            }
            a1 = BigInteger(ipType)
        }
        return arrayOf(a1, a2, a3)
    }

    private fun ipV4No(IP: String): Long {
        val ipArr = IP.split("\\.".toRegex()).toTypedArray()
        var retVal: Long = 0
        var ipLong: Long
        for (x in 3 downTo 0) {
            ipLong = ipArr[3 - x].toLong()
            retVal = retVal or (ipLong shl (x shl 3))
        }
        return retVal
    }

    companion object {
        private val Pattern1 =
                Pattern.compile("^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$") // IPv4
        private val Pattern2 =
                Pattern.compile("^([0-9A-F]{1,4}:){6}(0[0-9]+\\.|.*?\\.0[0-9]+).*$", Pattern.CASE_INSENSITIVE)
        private val Pattern3 = Pattern.compile("^[0-9]+$")
        private val Pattern4 = Pattern.compile("^(.*:)(([0-9]+\\.){3}[0-9]+)$")
        private val Pattern5 = Pattern.compile("^.*((:[0-9A-F]{1,4}){2})$")
        private val Pattern6 = Pattern.compile("^[0:]+((:[0-9A-F]{1,4}){1,2})$", Pattern.CASE_INSENSITIVE)
        private val Pattern7 = Pattern.compile("^([0-9]+\\.){1,2}[0-9]+$")
        private val MAX_IPV4_RANGE = BigInteger("4294967295")
        private val MAX_IPV6_RANGE = BigInteger("340282366920938463463374607431768211455")
        private val FROM_6TO4 = BigInteger("42545680458834377588178886921629466624")
        private val TO_6TO4 = BigInteger("42550872755692912415807417417958686719")
        private val FROM_TEREDO = BigInteger("42540488161975842760550356425300246528")
        private val TO_TEREDO = BigInteger("42540488241204005274814694018844196863")
        private val LAST_32BITS = BigInteger("4294967295")
        private const val MSG_NOT_SUPPORTED = "NOT SUPPORTED"
        private const val MSG_INVALID_IP = "INVALID IP ADDRESS"
        private const val MSG_MISSING_FILE = "MISSING FILE"
        private const val MSG_IPV6_UNSUPPORTED = "IPV6 ADDRESS MISSING IN IPV4 BIN"
        private val COUNTRY_POSITION = intArrayOf(0, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3)
        private val REGION_POSITION = intArrayOf(0, 0, 0, 4, 4, 4, 4, 4, 4, 4, 4, 4)
        private val CITY_POSITION = intArrayOf(0, 0, 0, 5, 5, 5, 5, 5, 5, 5, 5, 5)
        private val ISP_POSITION = intArrayOf(0, 0, 0, 0, 6, 6, 6, 6, 6, 6, 6, 6)
        private val PROXYTYPE_POSITION = intArrayOf(0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2)
        private val DOMAIN_POSITION = intArrayOf(0, 0, 0, 0, 0, 7, 7, 7, 7, 7, 7, 7)
        private val USAGETYPE_POSITION = intArrayOf(0, 0, 0, 0, 0, 0, 8, 8, 8, 8, 8, 8)
        private val ASN_POSITION = intArrayOf(0, 0, 0, 0, 0, 0, 0, 9, 9, 9, 9, 9)
        private val AS_POSITION = intArrayOf(0, 0, 0, 0, 0, 0, 0, 10, 10, 10, 10, 10)
        private val LASTSEEN_POSITION = intArrayOf(0, 0, 0, 0, 0, 0, 0, 0, 11, 11, 11, 11)
        private val THREAT_POSITION = intArrayOf(0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 12, 12)
        private val PROVIDER_POSITION = intArrayOf(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 13)
        private const val ModuleVersion = "3.2.0"
    }
}
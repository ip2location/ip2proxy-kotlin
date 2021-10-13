import com.google.gson.*
import java.lang.IllegalArgumentException
import java.net.URL
import java.net.URLEncoder
import java.util.regex.Pattern

class IP2ProxyWebService {
    private var _apiKey = ""
    private var _package = ""
    private var _useSSL = true
    /**
     * This function initializes the params for the web service.
     *
     * @param APIKey  IP2Proxy Web Service API key
     * @param Package IP2Proxy Web Service package (PX1 to PX11)
     * @param UseSSL  Set to true to call the web service using SSL
     * @throws IllegalArgumentException If an invalid parameter is specified
     */
    /**
     * This function initializes the params for the web service.
     *
     * @param APIKey  IP2Proxy Web Service API key
     * @param Package IP2Proxy Web Service package (PX1 to PX11)
     * @throws IllegalArgumentException If an invalid parameter is specified
     */
    @JvmOverloads
    @Throws(IllegalArgumentException::class)
    fun open(APIKey: String, Package: String, UseSSL: Boolean = true) {
        _apiKey = APIKey
        _package = Package
        _useSSL = UseSSL
        checkParams()
    }

    /**
     * This function validates the API key and package params.
     */
    @Throws(IllegalArgumentException::class)
    private fun checkParams() {
        require(pattern.matcher(_apiKey).matches()) { "Invalid API key." }
        require(pattern2.matcher(_package).matches()) { "Invalid package name." }
    }

    /**
     * This function to query IP2Proxy data.
     *
     * @param IPAddress IP Address you wish to query
     * @return IP2Proxy data
     * @throws IllegalArgumentException If an invalid parameter is specified
     * @throws RuntimeException         If an exception occurred at runtime
     */
    @Throws(IllegalArgumentException::class, RuntimeException::class)
    fun ipQuery(IPAddress: String?): JsonObject {
        return try {
            val myUrl: String
            checkParams() // check here in case user haven't called open yet
            val bf = StringBuffer()
            bf.append("http")
            if (_useSSL) {
                bf.append("s")
            }
            bf.append("://api.ip2proxy.com/?key=").append(_apiKey).append("&package=").append(_package).append("&ip=")
                .append(URLEncoder.encode(IPAddress, "UTF-8"))
            myUrl = bf.toString()
            val myJson: String = Http[URL(myUrl)]
            JsonParser.parseString(myJson).asJsonObject
        } catch (ex: IllegalArgumentException) {
            throw ex
        } catch (ex2: Exception) {
            throw RuntimeException(ex2)
        }
    }

    /**
     * This function to check web service credit balance.
     *
     * @return Credit balance
     * @throws IllegalArgumentException If an invalid parameter is specified
     * @throws RuntimeException         If an exception occurred at runtime
     */
    @Throws(IllegalArgumentException::class, RuntimeException::class)
    fun getCredit(): JsonObject {
        return try {
            val myUrl: String
            checkParams() // check here in case user haven't called open yet
            val bf = StringBuffer()
            bf.append("http")
            if (_useSSL) {
                bf.append("s")
            }
            bf.append("://api.ip2proxy.com/?key=").append(_apiKey).append("&check=true")
            myUrl = bf.toString()
            val myJson: String = Http[URL(myUrl)]
            JsonParser.parseString(myJson).asJsonObject
        } catch (ex: IllegalArgumentException) {
            throw ex
        } catch (ex2: Exception) {
            throw RuntimeException(ex2)
        }
    }

    companion object {
        private val pattern = Pattern.compile("^[\\dA-Z]{10}$")
        private val pattern2 = Pattern.compile("^PX\\d+$")
    }
}
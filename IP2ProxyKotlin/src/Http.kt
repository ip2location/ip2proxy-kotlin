import java.io.BufferedReader
import java.io.InputStreamReader
import java.lang.Exception
import java.lang.RuntimeException
import java.lang.StringBuilder
import java.net.HttpURLConnection
import java.net.URL

internal object Http {
    operator fun get(url: URL): String {
        return try {
            System.setProperty("https.protocols", "TLSv1.2")
            val conn = url.openConnection() as HttpURLConnection
            conn.requestMethod = "GET"
            conn.setRequestProperty("Accept", "application/json")
            if (conn.responseCode != 200) {
                return "Failed : HTTP error code : " + conn.responseCode
            }
            val br = BufferedReader(InputStreamReader(conn.inputStream))
            var output: String?
            val resultFromHttp = StringBuilder()
            while (br.readLine().also { output = it } != null) {
                resultFromHttp.append(output).append("\n")
            }
            br.close()
            conn.disconnect()
            resultFromHttp.toString()
        } catch (e: Exception) {
            throw RuntimeException(e)
        }
    }
}
package com.ip2proxy

import kotlin.test.Test
import kotlin.test.assertTrue

class IP2ProxyTest {
    @Test
    fun testUS() {
        try {
            val strIPAddress = "8.8.8.8"
            val resourceUrl = javaClass.getResource("/IP2PROXY-LITE-PX1.BIN")
            if (resourceUrl != null) {
                val file = java.io.File(resourceUrl.toURI())
                val dbPath = file.absolutePath

                val proxy = IP2Proxy()

                if (proxy.open(dbPath, IP2Proxy.IOModes.IP2PROXY_MEMORY_MAPPED) == 0) {
                    val all = proxy.getAll(strIPAddress)
                    assertTrue { all.isProxy == 0 }
                } else {
                    println("Error reading BIN file.")
                }
                proxy.close()
            }
        } catch (Ex: Exception) {
            println(Ex)
        }
    }
}

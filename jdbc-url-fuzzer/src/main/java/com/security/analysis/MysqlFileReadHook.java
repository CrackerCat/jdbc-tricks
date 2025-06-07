package com.security.analysis;

import com.code_intelligence.jazzer.api.HookType;
import com.code_intelligence.jazzer.api.MethodHook;

import java.lang.invoke.MethodHandle;

/**
 * Jazzer custom hook to intercept com.mysql.cj.protocol.a.NativeProtocol#sendFileToServer calls.
 * This hook checks if the fileName parameter is a sensitive file, like /etc/passwd.
 */
public class MysqlFileReadHook {

    /**
     * A hook that runs before the original sendFileToServer method.
     * It checks the file name being requested for "LOAD DATA LOCAL INFILE".
     *
     * @param method      A handle to the original method.
     * @param thisObject  The instance of the NativeProtocol class.
     * @param arguments   The arguments passed to the method. The first argument is the file name.
     * @param hookId      An identifier for the hook.
     * @throws RuntimeException if the file name is /etc/passwd, signaling a finding to Jazzer.
     */
    @MethodHook(
            targetClassName = "com.mysql.cj.protocol.a.NativeProtocol",
            targetMethod = "sendFileToServer",
            type = HookType.BEFORE
    )
    public static void beforeSendFileToServer(MethodHandle method,
                                              Object thisObject,
                                              Object[] arguments,
                                              int hookId) {

        // The fileName is the first argument of the sendFileToServer method.
        if (arguments.length > 0 && arguments[0] instanceof String) {
            String fileName = (String) arguments[0];

            System.out.println("[HOOK] sendFileToServer called with: " + fileName);
            // Check if the fuzzer is attempting to read /etc/passwd.
            if ("/etc/passwd".equals(fileName)) {
                // Throw a RuntimeException. Jazzer will catch this and report a finding.
                throw new RuntimeException("Fuzzing successful: Detected attempt to read /etc/passwd via LOAD DATA LOCAL INFILE.");
            }
        }
    }
}
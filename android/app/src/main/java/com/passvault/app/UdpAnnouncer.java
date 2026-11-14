package com.passvault.app;

import org.json.JSONObject;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;

/** 后台 UDP 广播：让电脑能在设备列表里发现这台手机 */
public class UdpAnnouncer {

    private static final int PORT = 53318;
    private static final String GROUP = "224.0.0.167";

    private final String deviceId;
    private final String name;
    private final int httpPort;

    private DatagramSocket socket;
    private Thread thread;
    private volatile boolean running = false;

    public UdpAnnouncer(String deviceId, String name, int httpPort) {
        this.deviceId = deviceId;
        this.name = name;
        this.httpPort = httpPort;
    }

    public void start() {
        running = true;
        thread = new Thread(() -> {
            try {
                socket = new DatagramSocket();
                socket.setBroadcast(true);
                InetAddress group = InetAddress.getByName(GROUP);
                InetAddress broadcast = InetAddress.getByName("255.255.255.255");
                while (running) {
                    JSONObject msg = new JSONObject();
                    msg.put("app", "dsh-passvault");
                    msg.put("v", 2);
                    msg.put("id", deviceId);
                    msg.put("name", name);
                    msg.put("http", httpPort);
                    msg.put("https", 0);
                    msg.put("platform", "android");
                    msg.put("ts", System.currentTimeMillis());
                    byte[] data = msg.toString().getBytes(StandardCharsets.UTF_8);
                    try {
                        socket.send(new DatagramPacket(data, data.length, group, PORT));
                    } catch (Exception ignored) {
                        // 组播失败时继续尝试广播
                    }
                    try {
                        socket.send(new DatagramPacket(data, data.length, broadcast, PORT));
                    } catch (Exception ignored) {
                        // 忽略
                    }
                    Thread.sleep(3000);
                }
            } catch (Exception ignored) {
                // 网络不可用时静默退出
            }
        }, "passvault-udp");
        thread.setDaemon(true);
        thread.start();
    }

    public void stop() {
        running = false;
        if (socket != null) socket.close();
    }
}

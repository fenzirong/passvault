package com.passvault.app;

import org.json.JSONArray;
import org.json.JSONObject;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.MulticastSocket;
import java.net.NetworkInterface;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * 后台 UDP 广播：让电脑能在设备列表里发现这台手机。
 *
 * v1.5.2 起改为「逐网卡定向广播 + 指定出口的组播」，并把自己的局域网地址
 * 一起发出去。旧实现只往 255.255.255.255 发一份，默认路由一旦走到移动数据 /
 * VPN / 虚拟网卡，包就永远到不了电脑 —— 这正是「同一 Wi-Fi 却互相发现不了」的原因。
 */
public class UdpAnnouncer {

    public static final int PORT = 53318;
    public static final String GROUP = "224.0.0.167";
    public static final String APP_ID = "dsh-passvault";

    private final String deviceId;
    private final String name;
    private final int httpPort;

    private Thread thread;
    private volatile boolean running = false;
    private volatile long lastSentAt = 0;

    public UdpAnnouncer(String deviceId, String name, int httpPort) {
        this.deviceId = deviceId == null ? "" : deviceId;
        this.name = name == null ? "安卓手机" : name;
        this.httpPort = httpPort;
    }

    public void start() {
        if (running) return;
        running = true;
        thread = new Thread(this::loop, "passvault-udp");
        thread.setDaemon(true);
        thread.start();
    }

    public void stop() {
        running = false;
        Thread t = thread;
        thread = null;
        if (t != null) t.interrupt();
    }

    public long lastSentAt() {
        return lastSentAt;
    }

    public boolean isRunning() {
        return running;
    }

    private void loop() {
        while (running) {
            try {
                sendOnce();
                lastSentAt = System.currentTimeMillis();
            } catch (Exception ignored) {
                // 网络切换期间发送失败属于正常现象，下一轮继续
            }
            try {
                Thread.sleep(3000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }

    /** 立即广播一次（网络恢复 / 对方主动探测时调用） */
    public void announceNow() {
        try {
            sendOnce();
            lastSentAt = System.currentTimeMillis();
        } catch (Exception ignored) {
            // 忽略
        }
    }

    /** 往某个地址单播一条通告（收到对方探测时的回应） */
    public void unicastTo(InetAddress target) {
        if (target == null) return;
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setBroadcast(true);
            byte[] data = payload().getBytes(StandardCharsets.UTF_8);
            socket.send(new DatagramPacket(data, data.length, target, PORT));
        } catch (Exception ignored) {
            // 忽略
        }
    }

    public String payload() {
        JSONObject msg = new JSONObject();
        try {
            msg.put("app", APP_ID);
            msg.put("v", 2);
            msg.put("id", deviceId);
            msg.put("name", name);
            msg.put("http", httpPort);
            msg.put("https", 0);
            msg.put("platform", "android");
            msg.put("addresses", new JSONArray(LanInterfaces.addresses()));
            msg.put("ts", System.currentTimeMillis());
        } catch (Exception ignored) {
            // 忽略
        }
        return msg.toString();
    }

    private void sendOnce() throws Exception {
        byte[] data = payload().getBytes(StandardCharsets.UTF_8);
        InetAddress group = InetAddress.getByName(GROUP);
        InetAddress limited = InetAddress.getByName("255.255.255.255");
        List<LanInterfaces.Entry> targets = LanInterfaces.sendTargets();

        if (targets.isEmpty()) {
            // 枚举不到网卡时退回旧行为，至少还有一次机会
            try (DatagramSocket socket = new DatagramSocket()) {
                socket.setBroadcast(true);
                socket.send(new DatagramPacket(data, data.length, limited, PORT));
                socket.send(new DatagramPacket(data, data.length, group, PORT));
            }
            return;
        }

        for (LanInterfaces.Entry entry : targets) {
            MulticastSocket socket = null;
            try {
                socket = new MulticastSocket();
                NetworkInterface nif = entry.nif;
                if (nif != null) {
                    try {
                        socket.setNetworkInterface(nif);
                    } catch (Exception ignored) {
                        // 个别网卡不允许设置出口
                    }
                }
                socket.setTimeToLive(1);
                // 1) 定向广播：这条路由由网卡自己决定，不会被默认路由抢走
                if (entry.broadcast != null) {
                    try {
                        socket.send(new DatagramPacket(data, data.length, entry.broadcast, PORT));
                    } catch (Exception ignored) {
                        // 忽略
                    }
                }
                // 2) 组播：出口已指向该网卡
                try {
                    socket.send(new DatagramPacket(data, data.length, group, PORT));
                } catch (Exception ignored) {
                    // 忽略
                }
                // 3) 受限广播兜底
                try {
                    socket.send(new DatagramPacket(data, data.length, limited, PORT));
                } catch (Exception ignored) {
                    // 忽略
                }
            } finally {
                if (socket != null) socket.close();
            }
        }
    }
}

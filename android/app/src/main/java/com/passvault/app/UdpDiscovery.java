package com.passvault.app;

import android.content.Context;
import android.net.wifi.WifiManager;

import org.json.JSONArray;
import org.json.JSONObject;

import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.MulticastSocket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** 后台监听局域网广播，供 App 内「附近的设备」使用 */
public class UdpDiscovery {

    private static final int PORT = 53318;
    private static final String GROUP = "224.0.0.167";
    private static final long TTL_MS = 15_000;

    private final Context context;
    private final String selfId;
    private final Map<String, JSONObject> peers = new ConcurrentHashMap<>();
    private WifiManager.MulticastLock multicastLock;
    private MulticastSocket socket;
    private Thread thread;
    private volatile boolean running = false;

    public UdpDiscovery(Context context, String selfId) {
        this.context = context;
        this.selfId = selfId == null ? "" : selfId;
    }

    public void start() {
        running = true;
        try {
            WifiManager wifi = (WifiManager) context.getApplicationContext().getSystemService(Context.WIFI_SERVICE);
            if (wifi != null) {
                multicastLock = wifi.createMulticastLock("passvault-discovery");
                multicastLock.setReferenceCounted(false);
                multicastLock.acquire();
            }
        } catch (Exception ignored) {
            // 没有权限时退化为仅收广播
        }

        thread = new Thread(() -> {
            try {
                socket = new MulticastSocket(null);
                socket.setReuseAddress(true);
                socket.bind(new InetSocketAddress(PORT));
                socket.setTimeToLive(1);
                try {
                    socket.joinGroup(InetAddress.getByName(GROUP));
                } catch (Exception ignored) {
                    // 部分设备不允许组播，仍可接收广播
                }
                byte[] buf = new byte[4096];
                while (running) {
                    DatagramPacket packet = new DatagramPacket(buf, buf.length);
                    socket.receive(packet);
                    try {
                        String text = new String(packet.getData(), 0, packet.getLength(), StandardCharsets.UTF_8);
                        JSONObject msg = new JSONObject(text);
                        if (!"dsh-passvault".equals(msg.optString("app"))) continue;
                        String id = msg.optString("id");
                        if (id.isEmpty() || id.equals(selfId)) continue;
                        msg.put("host", packet.getAddress().getHostAddress());
                        msg.put("lastSeen", System.currentTimeMillis());
                        peers.put(id, msg);
                    } catch (Exception ignored) {
                        // 单条报文异常忽略
                    }
                }
            } catch (Exception ignored) {
                // 端口被占用或网络不可用
            }
        }, "passvault-discovery");
        thread.setDaemon(true);
        thread.start();
    }

    public void stop() {
        running = false;
        if (socket != null) socket.close();
        try {
            if (multicastLock != null && multicastLock.isHeld()) multicastLock.release();
        } catch (Exception ignored) {
            // 忽略
        }
        multicastLock = null;
    }

    public JSONArray list() {
        long now = System.currentTimeMillis();
        List<JSONObject> out = new ArrayList<>();
        Iterator<Map.Entry<String, JSONObject>> it = peers.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<String, JSONObject> entry = it.next();
            JSONObject peer = entry.getValue();
            if (now - peer.optLong("lastSeen", 0) > TTL_MS) {
                it.remove();
                continue;
            }
            try {
                JSONObject item = new JSONObject();
                item.put("id", peer.optString("id"));
                item.put("name", peer.optString("name", "未命名设备"));
                item.put("host", peer.optString("host"));
                item.put("httpPort", peer.optInt("http", 8787));
                item.put("httpsPort", peer.optInt("https", 0));
                item.put("platform", peer.optString("platform", ""));
                out.add(item);
            } catch (Exception ignored) {
                // 忽略
            }
        }
        return new JSONArray(out);
    }
}

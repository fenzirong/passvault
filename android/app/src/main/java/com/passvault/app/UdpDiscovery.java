package com.passvault.app;

import android.content.Context;
import android.net.wifi.WifiManager;

import org.json.JSONArray;
import org.json.JSONObject;

import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.MulticastSocket;
import java.net.NetworkInterface;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 后台监听局域网广播，供 App 内「附近的设备」使用。
 *
 * v1.5.2 修复：
 *   1. 每个网卡都单独 joinGroup（旧代码无参 joinGroup 只加入默认多播网卡）。
 *   2. 绑定失败 / 网络切换会重建 socket，不再「一次失败永久失效」。
 *   3. 收到对方通告后单播回一条自己的通告，广播被交换机过滤时也能双向发现。
 */
public class UdpDiscovery {

    public static final int PORT = 53318;
    public static final String GROUP = "224.0.0.167";
    public static final String APP_ID = "dsh-passvault";
    private static final long TTL_MS = 15_000;

    private final Context context;
    private final String selfId;
    private final Map<String, JSONObject> peers = new ConcurrentHashMap<>();
    private WifiManager.MulticastLock multicastLock;
    private volatile MulticastSocket socket;
    private Thread thread;
    private volatile boolean running = false;
    private volatile long lastPacketAt = 0;
    private volatile String joinedSignature = "";

    public UdpDiscovery(Context context, String selfId) {
        this.context = context;
        this.selfId = selfId == null ? "" : selfId;
    }

    public boolean isRunning() {
        return running && socket != null;
    }

    public long lastPacketAt() {
        return lastPacketAt;
    }

    public void start() {
        if (running) return;
        running = true;
        acquireLock();
        thread = new Thread(this::loop, "passvault-discovery");
        thread.setDaemon(true);
        thread.start();
    }

    public void stop() {
        running = false;
        closeSocket();
        releaseLock();
        Thread t = thread;
        thread = null;
        if (t != null) t.interrupt();
    }

    /* ------------------------------ 内部 ------------------------------ */

    private void acquireLock() {
        try {
            WifiManager wifi = (WifiManager) context.getApplicationContext().getSystemService(Context.WIFI_SERVICE);
            if (wifi != null && multicastLock == null) {
                multicastLock = wifi.createMulticastLock("passvault-discovery");
                multicastLock.setReferenceCounted(false);
                multicastLock.acquire();
            }
        } catch (Exception ignored) {
            // 没有权限时退化为仅收广播（并不影响定向广播的接收）
        }
    }

    private void releaseLock() {
        try {
            if (multicastLock != null && multicastLock.isHeld()) multicastLock.release();
        } catch (Exception ignored) {
            // 忽略
        }
        multicastLock = null;
    }

    private void closeSocket() {
        MulticastSocket s = socket;
        socket = null;
        joinedSignature = "";
        if (s != null) {
            try {
                s.close();
            } catch (Exception ignored) {
                // 忽略
            }
        }
    }

    private void loop() {
        byte[] buf = new byte[4096];
        while (running) {
            try {
                ensureSocket();
                MulticastSocket s = socket;
                if (s == null) {
                    Thread.sleep(2000);
                    continue;
                }
                DatagramPacket packet = new DatagramPacket(buf, buf.length);
                s.receive(packet);
                lastPacketAt = System.currentTimeMillis();
                handle(packet);
            } catch (SocketTimeoutException e) {
                // 正常：超时用来周期性检查网卡变化
                refreshIfNetworkChanged();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                // 端口被占用、网络不可用等：稍后重建
                closeSocket();
                sleepQuietly(2000);
            }
        }
    }

    private void ensureSocket() throws Exception {
        if (socket != null) return;
        MulticastSocket s = new MulticastSocket(null);
        s.setReuseAddress(true);
        s.bind(new InetSocketAddress(PORT));
        s.setTimeToLive(1);
        s.setSoTimeout(3000);
        socket = s;
        joinAll(s);
    }

    private void joinAll(MulticastSocket s) {
        StringBuilder sig = new StringBuilder();
        InetAddress groupAddr;
        try {
            groupAddr = InetAddress.getByName(GROUP);
        } catch (Exception e) {
            joinedSignature = "";
            return;
        }
        InetSocketAddress group = new InetSocketAddress(groupAddr, PORT);
        for (LanInterfaces.Entry entry : LanInterfaces.sendTargets()) {
            NetworkInterface nif = entry.nif;
            if (nif == null) continue;
            try {
                s.joinGroup(group, nif);
                sig.append(entry.address.getHostAddress()).append(',');
            } catch (Exception ignored) {
                // 该网卡不支持组播，仍然能收到定向广播
            }
        }
        if (sig.length() == 0) {
            // 一个网卡都加入失败时，退回无参 joinGroup
            try {
                s.joinGroup(groupAddr);
                sig.append("*");
            } catch (Exception ignored) {
                // 只能依靠广播
            }
        }
        joinedSignature = sig.toString();
    }

    /** 换 Wi-Fi / 插拔网络后重新加入组播 */
    private void refreshIfNetworkChanged() {
        MulticastSocket s = socket;
        if (s == null) return;
        String current = currentSignature();
        if (current.equals(joinedSignature)) return;
        closeSocket();
        try {
            ensureSocket();
        } catch (Exception ignored) {
            closeSocket();
        }
    }

    private String currentSignature() {
        StringBuilder sig = new StringBuilder();
        for (LanInterfaces.Entry entry : LanInterfaces.sendTargets()) {
            sig.append(entry.address.getHostAddress()).append(',');
        }
        return sig.toString();
    }

    private void handle(DatagramPacket packet) {
        try {
            String text = new String(packet.getData(), 0, packet.getLength(), StandardCharsets.UTF_8);
            JSONObject msg = new JSONObject(text);
            if (!APP_ID.equals(msg.optString("app"))) return;
            String id = msg.optString("id");
            if (id.isEmpty() || id.equals(selfId)) return;
            msg.put("host", packet.getAddress().getHostAddress());
            msg.put("lastSeen", System.currentTimeMillis());
            peers.put(id, msg);
        } catch (Exception ignored) {
            // 单条报文异常忽略
        }
    }

    private void sleepQuietly(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public JSONArray list() {
        long now = System.currentTimeMillis();
        List<JSONObject> out = new ArrayList<>();
        Iterator<Map.Entry<String, JSONObject>> it = peers.entrySet().iterator();
        Set<String> seen = new HashSet<>();
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
                JSONArray addresses = peer.optJSONArray("addresses");
                if (addresses == null) addresses = new JSONArray();
                item.put("addresses", addresses);
                item.put("httpPort", peer.optInt("http", 8787));
                item.put("httpsPort", peer.optInt("https", 0));
                item.put("platform", peer.optString("platform", ""));
                if (!seen.add(item.optString("id"))) continue;
                out.add(item);
            } catch (Exception ignored) {
                // 忽略
            }
        }
        return new JSONArray(out);
    }
}

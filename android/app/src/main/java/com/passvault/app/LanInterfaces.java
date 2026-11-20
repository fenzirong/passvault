package com.passvault.app;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

/**
 * 局域网网卡枚举。
 *
 * 安卓上「同一 Wi-Fi 却收不到广播」的常见原因：手机同时开着移动数据或 VPN，
 * 默认路由走了蜂窝 / 隧道，DatagramSocket 往 255.255.255.255 发的那一份就从错误
 * 的接口出去了。这里逐个网卡算出定向广播地址，发送时显式指定接口。
 */
public final class LanInterfaces {

    private LanInterfaces() {}

    public static final class Entry {
        public final NetworkInterface nif;
        public final InetAddress address;
        public final InetAddress broadcast;
        public final int prefixLength;
        public final boolean loopback;
        public final boolean virtual;

        Entry(
            NetworkInterface nif,
            InetAddress address,
            InetAddress broadcast,
            int prefixLength,
            boolean loopback,
            boolean virtual
        ) {
            this.nif = nif;
            this.address = address;
            this.broadcast = broadcast;
            this.prefixLength = prefixLength;
            this.loopback = loopback;
            this.virtual = virtual;
        }

        public String name() {
            return nif == null ? "" : nif.getName();
        }
    }

    /** 虚拟 / 隧道网卡名（这些网卡上的广播到不了真实局域网） */
    private static final String[] VIRTUAL_KEYS = {
        "rmnet", "ccmni", "pdp", "clat", "dummy", "sit", "ip6tnl",
        "tun", "tap", "ppp", "p2p", "docker", "vbox", "vmnet",
        "wg", "tailscale", "zt", "vpn", "rev-tun"
    };

    public static boolean isVirtual(String name) {
        if (name == null) return true;
        String lower = name.toLowerCase();
        if (lower.equals("lo")) return true;
        for (String key : VIRTUAL_KEYS) {
            if (lower.startsWith(key) || lower.contains(key)) return true;
        }
        return false;
    }

    /** 可用网卡：真实网卡在前，虚拟网卡在后 */
    public static List<Entry> candidates() {
        List<Entry> real = new ArrayList<>();
        List<Entry> virtual = new ArrayList<>();
        try {
            Enumeration<NetworkInterface> all = NetworkInterface.getNetworkInterfaces();
            if (all == null) return real;
            for (NetworkInterface nif : Collections.list(all)) {
                try {
                    if (!nif.isUp()) continue;
                    for (InterfaceAddress ia : nif.getInterfaceAddresses()) {
                        InetAddress addr = ia.getAddress();
                        if (!(addr instanceof Inet4Address)) continue;
                        if (addr.isLoopbackAddress() || addr.isLinkLocalAddress()) continue;
                        Entry entry = new Entry(
                            nif,
                            addr,
                            ia.getBroadcast(),
                            ia.getNetworkPrefixLength(),
                            nif.isLoopback(),
                            isVirtual(nif.getName())
                        );
                        (entry.virtual ? virtual : real).add(entry);
                    }
                } catch (Exception ignored) {
                    // 单个网卡异常忽略
                }
            }
        } catch (Exception ignored) {
            // 权限或系统限制
        }
        List<Entry> out = new ArrayList<>(real);
        out.addAll(virtual);
        return out;
    }

    /** 发送目标：有真实网卡就只发真实网卡 */
    public static List<Entry> sendTargets() {
        List<Entry> all = candidates();
        List<Entry> real = new ArrayList<>();
        for (Entry e : all) {
            if (!e.virtual) real.add(e);
        }
        return real.isEmpty() ? all : real;
    }

    /** 本机局域网 IPv4 地址列表 */
    public static List<String> addresses() {
        List<String> out = new ArrayList<>();
        for (Entry e : candidates()) {
            String ip = e.address.getHostAddress();
            if (!out.contains(ip)) out.add(ip);
        }
        return out;
    }
}

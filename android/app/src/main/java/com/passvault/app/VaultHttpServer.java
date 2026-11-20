package com.passvault.app;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * 极简 HTTP 服务：让手机在后台也能被局域网内的其他设备访问。
 * 只实现 /api/info、/api/vault、/api/discovery 三个接口。
 */
public class VaultHttpServer {

    public interface Listener {
        void onVaultUpdated(JSONObject envelope);
    }

    private final VaultStore store;
    private volatile String pairingCode;
    private final String deviceId;
    private volatile String deviceName;
    private final Listener listener;

    private ServerSocket serverSocket;
    private Thread acceptThread;
    private final ExecutorService pool = Executors.newFixedThreadPool(4);
    private volatile boolean running = false;
    private int port = 0;

    public VaultHttpServer(
        VaultStore store,
        String pairingCode,
        String deviceId,
        String deviceName,
        Listener listener
    ) {
        this.store = store;
        this.pairingCode = pairingCode == null ? "" : pairingCode;
        this.deviceId = deviceId;
        this.deviceName = deviceName;
        this.listener = listener;
    }

    public int getPort() {
        return port;
    }

    /** 页面里重新生成配对码后同步到运行中的服务，不再需要重启 */
    public void updateAuth(String code) {
        if (code != null && !code.isEmpty()) this.pairingCode = code;
    }

    public void setDeviceName(String name) {
        if (name != null && !name.isEmpty()) this.deviceName = name;
    }

    /**
     * 端口从 8787 开始顺延，避免上个实例没退干净（或别的 App 占用）时
     * 整个后台服务直接失效 —— 那会让手机彻底无法被发现。
     */
    public void start() throws IOException {
        int[] candidates = { 8787, 8788, 8789, 8790, 0 };
        IOException last = null;
        for (int candidate : candidates) {
            ServerSocket socket = new ServerSocket();
            try {
                socket.setReuseAddress(true);
                socket.bind(new InetSocketAddress(candidate));
                serverSocket = socket;
                port = socket.getLocalPort();
                running = true;
                acceptThread = new Thread(this::acceptLoop, "passvault-http");
                acceptThread.setDaemon(true);
                acceptThread.start();
                return;
            } catch (IOException e) {
                last = e;
                try {
                    socket.close();
                } catch (IOException ignored) {
                    // 忽略
                }
            }
        }
        throw last != null ? last : new IOException("没有可用端口");
    }

    public void stop() {
        running = false;
        try {
            if (serverSocket != null) serverSocket.close();
        } catch (IOException ignored) {
            // 忽略
        }
        pool.shutdownNow();
    }

    private void acceptLoop() {
        while (running) {
            try {
                Socket socket = serverSocket.accept();
                pool.execute(() -> handle(socket));
            } catch (IOException e) {
                if (running) {
                    try {
                        Thread.sleep(200);
                    } catch (InterruptedException ignored) {
                        Thread.currentThread().interrupt();
                    }
                }
            }
        }
    }

    private void handle(Socket socket) {
        try (Socket s = socket) {
            s.setSoTimeout(15000);
            InputStream in = s.getInputStream();
            OutputStream out = s.getOutputStream();

            String head = readHead(in);
            if (head == null || head.isEmpty()) return;

            String[] lines = head.split("\r\n");
            String[] requestLine = lines[0].split(" ");
            if (requestLine.length < 2) return;
            String method = requestLine[0].toUpperCase(Locale.ROOT);
            String path = requestLine[1];
            int q = path.indexOf('?');
            if (q >= 0) path = path.substring(0, q);

            Map<String, String> headers = new HashMap<>();
            for (int i = 1; i < lines.length; i++) {
                int idx = lines[i].indexOf(':');
                if (idx > 0) {
                    headers.put(
                        lines[i].substring(0, idx).trim().toLowerCase(Locale.ROOT),
                        lines[i].substring(idx + 1).trim()
                    );
                }
            }

            if ("OPTIONS".equals(method)) {
                respond(out, 204, "");
                return;
            }

            if ("/api/info".equals(path)) {
                JSONObject info = new JSONObject();
                info.put("app", "dsh-passvault");
                info.put("version", 2);
                info.put("name", deviceName);
                info.put("deviceId", deviceId);
                info.put("revision", store.getRevision());
                info.put("updatedAt", store.getUpdatedAt() == null ? JSONObject.NULL : store.getUpdatedAt());
                info.put("hasVault", store.getEnvelope() != null);
                info.put("authRequired", true);
                info.put("platform", "android");
                respond(out, 200, info.toString());
                return;
            }

            if ("/api/discovery".equals(path)) {
                JSONObject self = new JSONObject();
                self.put("id", deviceId);
                self.put("name", deviceName);
                self.put("httpPort", port);
                self.put("httpsPort", 0);
                self.put("platform", "android");
                self.put("addresses", new org.json.JSONArray(LanInterfaces.addresses()));
                JSONObject res = new JSONObject();
                res.put("self", self);
                res.put("peers", new org.json.JSONArray());
                respond(out, 200, res.toString());
                return;
            }

            if (!"/api/vault".equals(path)) {
                respond(out, 404, "{\"error\":\"接口不存在\"}");
                return;
            }

            String provided = headers.getOrDefault("x-pair-code", headers.getOrDefault("x-sync-token", ""));
            if (!pairingCode.isEmpty() && !pairingCode.equals(provided)) {
                respond(out, 401, "{\"error\":\"配对码不正确\"}");
                return;
            }

            if ("GET".equals(method)) {
                JSONObject env = store.getEnvelope();
                if (env == null) {
                    respond(out, 404, "{\"error\":\"还没有保险库\"}");
                    return;
                }
                respond(out, 200, env.toString());
                return;
            }

            if ("PUT".equals(method)) {
                String ifMatch = headers.get("if-match");
                if (ifMatch == null) {
                    respond(out, 428, "{\"error\":\"缺少 If-Match 版本号\"}");
                    return;
                }
                int expected;
                try {
                    expected = Integer.parseInt(ifMatch.replace("\"", ""));
                } catch (NumberFormatException e) {
                    respond(out, 400, "{\"error\":\"If-Match 版本号无效\"}");
                    return;
                }
                if (expected != store.getRevision()) {
                    JSONObject err = new JSONObject();
                    err.put("error", "版本冲突");
                    err.put("revision", store.getRevision());
                    respond(out, 409, err.toString());
                    return;
                }
                int length = 0;
                try {
                    length = Integer.parseInt(headers.getOrDefault("content-length", "0"));
                } catch (NumberFormatException ignored) {
                    // 忽略
                }
                byte[] body = readBody(in, length);
                JSONObject envelope;
                try {
                    envelope = new JSONObject(new String(body, StandardCharsets.UTF_8));
                } catch (Exception e) {
                    respond(out, 400, "{\"error\":\"请求体不是合法 JSON\"}");
                    return;
                }
                JSONObject header = envelope.optJSONObject("header");
                if (
                    !"dsh-passvault".equals(envelope.optString("format")) ||
                    header == null ||
                    header.optInt("revision", -1) != expected + 1
                ) {
                    respond(out, 400, "{\"error\":\"保险库格式不正确，或版本号不连续\"}");
                    return;
                }
                store.setEnvelope(envelope);
                if (listener != null) listener.onVaultUpdated(envelope);
                JSONObject ok = new JSONObject();
                ok.put("ok", true);
                ok.put("revision", store.getRevision());
                respond(out, 200, ok.toString());
                return;
            }

            respond(out, 405, "{\"error\":\"不支持的请求方法\"}");
        } catch (Exception ignored) {
            // 单个连接异常不影响服务
        }
    }

    private String readHead(InputStream in) throws IOException {
        ByteArrayOutputStream head = new ByteArrayOutputStream();
        int p3 = 0, p2 = 0, p1 = 0, c;
        while ((c = in.read()) != -1) {
            head.write(c);
            if (p3 == '\r' && p2 == '\n' && p1 == '\r' && c == '\n') break;
            p3 = p2;
            p2 = p1;
            p1 = c;
            if (head.size() > 65536) break;
        }
        return head.toString("UTF-8");
    }

    private byte[] readBody(InputStream in, int length) throws IOException {
        byte[] body = new byte[Math.max(0, length)];
        int read = 0;
        while (read < body.length) {
            int n = in.read(body, read, body.length - read);
            if (n < 0) break;
            read += n;
        }
        return body;
    }

    private void respond(OutputStream out, int status, String json) throws IOException {
        byte[] body = json.getBytes(StandardCharsets.UTF_8);
        String head =
            "HTTP/1.1 " +
            status +
            " " +
            statusText(status) +
            "\r\n" +
            "Content-Type: application/json; charset=utf-8\r\n" +
            "Content-Length: " +
            body.length +
            "\r\n" +
            "Access-Control-Allow-Origin: *\r\n" +
            "Access-Control-Allow-Headers: Content-Type, X-Sync-Token, X-Pair-Code, If-Match\r\n" +
            "Access-Control-Allow-Methods: GET, PUT, OPTIONS\r\n" +
            "Access-Control-Expose-Headers: ETag\r\n" +
            "Cache-Control: no-store\r\n" +
            "Connection: close\r\n\r\n";
        out.write(head.getBytes(StandardCharsets.UTF_8));
        out.write(body);
        out.flush();
    }

    private String statusText(int status) {
        switch (status) {
            case 200:
                return "OK";
            case 204:
                return "No Content";
            case 400:
                return "Bad Request";
            case 401:
                return "Unauthorized";
            case 404:
                return "Not Found";
            case 405:
                return "Method Not Allowed";
            case 409:
                return "Conflict";
            case 428:
                return "Precondition Required";
            default:
                return "OK";
        }
    }
}

package com.passvault.app;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.IBinder;

import androidx.core.app.NotificationCompat;

import org.json.JSONObject;

/**
 * 前台服务：让手机在后台也能被局域网内的设备访问。
 * 常驻通知栏显示「密码保险库正在运行」。
 */
public class PassVaultService extends Service {

    public static final String CHANNEL_ID = "passvault_server";
    public static final int NOTIFICATION_ID = 4242;

    public static VaultStore store;
    public static VaultHttpServer server;
    public static UdpAnnouncer announcer;
    public static UdpDiscovery discovery;
    public static int port = 0;
    public static String pairingCode = "";
    public static String deviceId = "";
    public static String deviceName = "安卓手机";
    public static PassVaultServerPlugin plugin;

    private Thread watchdog;
    private volatile boolean watchdogRunning = false;

    @Override
    public void onCreate() {
        super.onCreate();
        createChannel();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null) {
            String code = intent.getStringExtra("code");
            String id = intent.getStringExtra("deviceId");
            String name = intent.getStringExtra("name");
            if (code != null) pairingCode = code;
            if (id != null) deviceId = id;
            if (name != null) deviceName = name;
        }

        Notification notification = buildNotification();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC);
        } else {
            startForeground(NOTIFICATION_ID, notification);
        }

        startComponents();
        startWatchdog();
        return START_STICKY;
    }

    /**
     * 启动 HTTP 服务 + 广播 + 发现。任何一步失败都不影响其他步骤，
     * 失败的步骤交给看门狗下一轮重试 —— 旧实现一旦抛异常就永久 port=0，
     * 手机从此在局域网里彻底「隐身」。
     */
    private void startComponents() {
        if (store == null) store = new VaultStore(this);

        if (server == null) {
            VaultHttpServer instance = new VaultHttpServer(
                store,
                pairingCode,
                deviceId,
                deviceName,
                this::emitVaultUpdated
            );
            try {
                instance.start();
                server = instance;
                port = instance.getPort();
            } catch (Exception e) {
                try {
                    instance.stop();
                } catch (Exception ignored) {
                    // 忽略
                }
                server = null;
                port = 0;
            }
        } else {
            server.updateAuth(pairingCode);
            server.setDeviceName(deviceName);
            port = server.getPort();
        }

        if (port > 0) {
            if (announcer == null || !announcer.isRunning()) {
                announcer = new UdpAnnouncer(deviceId, deviceName, port);
                announcer.start();
            }
            if (discovery == null || !discovery.isRunning()) {
                discovery = new UdpDiscovery(this, deviceId);
                discovery.start();
            }
        }
    }

    private void emitVaultUpdated(JSONObject envelope) {
        PassVaultServerPlugin p = plugin;
        if (p == null) return;
        try {
            JSONObject data = new JSONObject();
            data.put("envelope", envelope);
            p.emitVaultUpdated(data);
        } catch (Exception ignored) {
            // 忽略
        }
    }

    /** 每 10 秒自检：端口掉了、广播线程死了、发现线程死了都会自动拉起 */
    private void startWatchdog() {
        if (watchdogRunning) return;
        watchdogRunning = true;
        watchdog = new Thread(() -> {
            while (watchdogRunning) {
                try {
                    Thread.sleep(10_000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
                if (!watchdogRunning) break;
                try {
                    if (port == 0 || server == null) {
                        if (server != null) {
                            try {
                                server.stop();
                            } catch (Exception ignored) {
                                // 忽略
                            }
                            server = null;
                        }
                    }
                    startComponents();
                } catch (Exception ignored) {
                    // 看门狗自己不能死
                }
            }
        }, "passvault-watchdog");
        watchdog.setDaemon(true);
        watchdog.start();
    }

    @Override
    public void onDestroy() {
        watchdogRunning = false;
        Thread wd = watchdog;
        watchdog = null;
        if (wd != null) wd.interrupt();
        if (announcer != null) {
            announcer.stop();
            announcer = null;
        }
        if (discovery != null) {
            discovery.stop();
            discovery = null;
        }
        if (server != null) {
            server.stop();
            server = null;
        }
        port = 0;
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    private void createChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                CHANNEL_ID,
                "局域网同步服务",
                NotificationManager.IMPORTANCE_LOW
            );
            channel.setDescription("保持手机可被局域网内的其他设备访问");
            NotificationManager manager = getSystemService(NotificationManager.class);
            if (manager != null) manager.createNotificationChannel(channel);
        }
    }

    private Notification buildNotification() {
        return new NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("密码保险库正在运行")
            .setContentText("局域网内的设备可以发现并同步这台手机")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build();
    }
}

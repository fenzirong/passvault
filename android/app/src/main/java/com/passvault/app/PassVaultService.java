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
    public static int port = 0;
    public static String pairingCode = "";
    public static String deviceId = "";
    public static String deviceName = "安卓手机";
    public static PassVaultServerPlugin plugin;

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

        if (server == null) {
            store = new VaultStore(this);
            server = new VaultHttpServer(store, pairingCode, deviceId, deviceName, envelope -> {
                PassVaultServerPlugin p = plugin;
                if (p != null) {
                    JSONObject data = new JSONObject();
                    try {
                        data.put("envelope", envelope);
                    } catch (Exception ignored) {
                        // 忽略
                    }
                    p.emitVaultUpdated(data);
                }
            });
            try {
                server.start();
                port = server.getPort();
                announcer = new UdpAnnouncer(deviceId, deviceName, port);
                announcer.start();
            } catch (Exception e) {
                port = 0;
            }
        }
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        if (announcer != null) {
            announcer.stop();
            announcer = null;
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

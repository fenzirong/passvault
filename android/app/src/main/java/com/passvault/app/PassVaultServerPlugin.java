package com.passvault.app;

import android.content.Intent;

import androidx.core.content.ContextCompat;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

import org.json.JSONArray;
import org.json.JSONObject;

/** 控制后台同步服务：启动 / 停止 / 更新保险库 / 查询状态 */
@CapacitorPlugin(name = "PassVaultServer")
public class PassVaultServerPlugin extends Plugin {

    @PluginMethod
    public void start(PluginCall call) {
        PassVaultService.plugin = this;
        Intent intent = new Intent(getContext(), PassVaultService.class);
        intent.putExtra("code", call.getString("code", ""));
        intent.putExtra("deviceId", call.getString("deviceId", ""));
        intent.putExtra("name", call.getString("name", "安卓手机"));
        try {
            ContextCompat.startForegroundService(getContext(), intent);
        } catch (Exception e) {
            call.reject("启动后台服务失败：" + e.getMessage());
            return;
        }
        new Thread(() -> {
            for (int i = 0; i < 50; i++) {
                if (PassVaultService.port > 0) break;
                try {
                    Thread.sleep(100);
                } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                }
            }
            JSObject ret = new JSObject();
            ret.put("running", PassVaultService.port > 0);
            ret.put("port", PassVaultService.port);
            call.resolve(ret);
        }).start();
    }

    @PluginMethod
    public void stop(PluginCall call) {
        try {
            getContext().stopService(new Intent(getContext(), PassVaultService.class));
        } catch (Exception ignored) {
            // 忽略
        }
        call.resolve();
    }

    @PluginMethod
    public void updateVault(PluginCall call) {
        JSObject envelope = call.getObject("envelope");
        if (envelope == null) {
            call.reject("缺少 envelope");
            return;
        }
        try {
            if (PassVaultService.store == null) {
                PassVaultService.store = new VaultStore(getContext());
            }
            PassVaultService.store.setEnvelope(new JSONObject(envelope.toString()));
            JSObject ret = new JSObject();
            ret.put("revision", PassVaultService.store.getRevision());
            call.resolve(ret);
        } catch (Exception e) {
            call.reject("写入失败：" + e.getMessage());
        }
    }

    @PluginMethod
    public void getVault(PluginCall call) {
        JSObject ret = new JSObject();
        try {
            if (PassVaultService.store == null) {
                PassVaultService.store = new VaultStore(getContext());
            }
            JSONObject env = PassVaultService.store.getEnvelope();
            ret.put("revision", PassVaultService.store.getRevision());
            ret.put("envelope", env == null ? null : new JSObject(env.toString()));
        } catch (Exception e) {
            ret.put("revision", 0);
            ret.put("envelope", null);
        }
        call.resolve(ret);
    }

    @PluginMethod
    public void peers(PluginCall call) {
        JSObject ret = new JSObject();
        JSONArray list = PassVaultService.discovery != null
            ? PassVaultService.discovery.list()
            : new JSONArray();
        ret.put("peers", list);
        call.resolve(ret);
    }

    @PluginMethod
    public void status(PluginCall call) {
        JSObject ret = new JSObject();
        ret.put("running", PassVaultService.port > 0);
        ret.put("port", PassVaultService.port);
        ret.put("revision", PassVaultService.store != null ? PassVaultService.store.getRevision() : 0);
        ret.put("code", PassVaultService.pairingCode);
        call.resolve(ret);
    }

    /** 由后台服务在收到其他设备推送时调用 */
    void emitVaultUpdated(JSONObject data) {
        try {
            notifyListeners("vaultUpdated", new JSObject(data.toString()));
        } catch (Exception ignored) {
            // 忽略
        }
    }
}

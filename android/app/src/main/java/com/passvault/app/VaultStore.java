package com.passvault.app;

import android.content.Context;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;

/** 手机端保险库存储：只保存密文信封，供后台 HTTP 服务读写 */
public class VaultStore {

    private final File file;
    private JSONObject envelope;
    private int revision;
    private String updatedAt;

    public VaultStore(Context context) {
        file = new File(context.getFilesDir(), "vault.json");
        load();
    }

    private synchronized void load() {
        try (FileInputStream in = new FileInputStream(file)) {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) bos.write(buf, 0, n);
            JSONObject obj = new JSONObject(bos.toString("UTF-8"));
            envelope = obj.optJSONObject("envelope");
            revision = obj.optInt("revision", 0);
            updatedAt = obj.optString("updatedAt", null);
        } catch (Exception ignored) {
            // 首次运行
        }
    }

    public synchronized JSONObject getEnvelope() {
        return envelope;
    }

    public synchronized int getRevision() {
        return revision;
    }

    public synchronized String getUpdatedAt() {
        return updatedAt;
    }

    public synchronized void setEnvelope(JSONObject env) {
        envelope = env;
        JSONObject header = env.optJSONObject("header");
        if (header != null) {
            revision = header.optInt("revision", revision);
            updatedAt = header.optString("updatedAt", updatedAt);
        }
        try (FileOutputStream out = new FileOutputStream(file)) {
            JSONObject obj = new JSONObject();
            obj.put("envelope", env);
            obj.put("revision", revision);
            obj.put("updatedAt", updatedAt == null ? "" : updatedAt);
            out.write(obj.toString().getBytes("UTF-8"));
        } catch (Exception ignored) {
            // 写入失败时保留内存副本
        }
    }
}

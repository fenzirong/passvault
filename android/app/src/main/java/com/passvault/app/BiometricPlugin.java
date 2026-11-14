package com.passvault.app;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * 安卓原生生物识别：用 BiometricPrompt 解锁 Android Keystore 中的 AES 密钥，
 * 再用它加解密「保险库主密钥」，实现指纹 / 面容解锁。
 */
@CapacitorPlugin(name = "PassVaultBiometric")
public class BiometricPlugin extends Plugin {

    private static final String KEY_ALIAS = "passvault_bio_key";
    private static final String PREFS = "passvault_bio";
    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";

    private interface ResultHandler {
        void onSuccess(Cipher cipher);
    }

    @PluginMethod
    public void isAvailable(PluginCall call) {
        JSObject ret = new JSObject();
        try {
            BiometricManager bm = BiometricManager.from(getContext());
            int result = bm.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG);
            ret.put("available", result == BiometricManager.BIOMETRIC_SUCCESS);
            ret.put("code", result);
        } catch (Exception e) {
            ret.put("available", false);
            ret.put("error", e.getMessage());
        }
        call.resolve(ret);
    }

    @PluginMethod
    public void save(PluginCall call) {
        final String key = call.getString("key", "vault-key");
        final String value = call.getString("value");
        if (value == null) {
            call.reject("缺少 value");
            return;
        }
        call.setKeepAlive(true);
        try {
            final Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey());
            prompt(call, "启用生物识别", cipher, c -> {
                try {
                    byte[] encrypted = c.doFinal(value.getBytes(StandardCharsets.UTF_8));
                    SharedPreferences prefs = getContext().getSharedPreferences(PREFS, Context.MODE_PRIVATE);
                    prefs
                        .edit()
                        .putString(key + "_iv", Base64.encodeToString(c.getIV(), Base64.NO_WRAP))
                        .putString(key + "_data", Base64.encodeToString(encrypted, Base64.NO_WRAP))
                        .apply();
                    call.resolve();
                } catch (Exception e) {
                    call.reject("保存失败：" + e.getMessage());
                }
            });
        } catch (Exception e) {
            call.reject("初始化失败：" + e.getMessage());
        }
    }

    @PluginMethod
    public void load(PluginCall call) {
        final String key = call.getString("key", "vault-key");
        SharedPreferences prefs = getContext().getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        final String ivB64 = prefs.getString(key + "_iv", null);
        final String dataB64 = prefs.getString(key + "_data", null);
        if (ivB64 == null || dataB64 == null) {
            call.reject("尚未保存生物识别密钥");
            return;
        }
        call.setKeepAlive(true);
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(
                Cipher.DECRYPT_MODE,
                getOrCreateKey(),
                new GCMParameterSpec(128, Base64.decode(ivB64, Base64.NO_WRAP))
            );
            prompt(call, "解锁保险库", cipher, c -> {
                try {
                    byte[] plain = c.doFinal(Base64.decode(dataB64, Base64.NO_WRAP));
                    JSObject ret = new JSObject();
                    ret.put("value", new String(plain, StandardCharsets.UTF_8));
                    call.resolve(ret);
                } catch (Exception e) {
                    call.reject("解密失败：" + e.getMessage());
                }
            });
        } catch (Exception e) {
            call.reject("初始化失败：" + e.getMessage());
        }
    }

    @PluginMethod
    public void delete(PluginCall call) {
        String key = call.getString("key", "vault-key");
        SharedPreferences prefs = getContext().getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        prefs.edit().remove(key + "_iv").remove(key + "_data").apply();
        try {
            KeyStore ks = KeyStore.getInstance(ANDROID_KEYSTORE);
            ks.load(null);
            if (ks.containsAlias(KEY_ALIAS)) ks.deleteEntry(KEY_ALIAS);
        } catch (Exception ignored) {
            // 忽略
        }
        call.resolve();
    }

    private void prompt(PluginCall call, String title, Cipher cipher, ResultHandler handler) {
        getActivity().runOnUiThread(() -> {
            BiometricPrompt.PromptInfo info = new BiometricPrompt.PromptInfo.Builder()
                .setTitle(title)
                .setSubtitle("密码保险库")
                .setNegativeButtonText("取消")
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .build();

            BiometricPrompt prompt = new BiometricPrompt(
                (androidx.fragment.app.FragmentActivity) getActivity(),
                ContextCompat.getMainExecutor(getContext()),
                new BiometricPrompt.AuthenticationCallback() {
                    @Override
                    public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
                        Cipher c = result.getCryptoObject() != null
                            ? result.getCryptoObject().getCipher()
                            : cipher;
                        handler.onSuccess(c);
                    }

                    @Override
                    public void onAuthenticationError(int errorCode, CharSequence errString) {
                        call.reject("生物识别失败：" + errString);
                    }

                    @Override
                    public void onAuthenticationFailed() {
                        // 识别失败但可重试，保持提示框
                    }
                }
            );
            prompt.authenticate(info, new BiometricPrompt.CryptoObject(cipher));
        });
    }

    private SecretKey getOrCreateKey() throws Exception {
        KeyStore ks = KeyStore.getInstance(ANDROID_KEYSTORE);
        ks.load(null);
        if (ks.containsAlias(KEY_ALIAS)) {
            return (SecretKey) ks.getKey(KEY_ALIAS, null);
        }
        KeyGenerator kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE);
        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setInvalidatedByBiometricEnrollment(true);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG);
        } else {
            builder.setUserAuthenticationRequired(true);
        }
        kg.init(builder.build());
        return kg.generateKey();
    }
}

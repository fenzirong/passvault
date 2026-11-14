package com.passvault.app;

import android.os.Bundle;

import com.getcapacitor.BridgeActivity;

public class MainActivity extends BridgeActivity {
    @Override
    public void onCreate(Bundle savedInstanceState) {
        registerPlugin(BiometricPlugin.class);
        registerPlugin(PassVaultServerPlugin.class);
        super.onCreate(savedInstanceState);
    }
}

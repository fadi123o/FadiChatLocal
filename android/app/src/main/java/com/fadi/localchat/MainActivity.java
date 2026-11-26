package com.fadi.localchat;

import android.Manifest;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.webkit.JavascriptInterface;
import android.webkit.PermissionRequest;
import android.webkit.WebChromeClient;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import org.json.JSONArray;
import org.json.JSONObject;

public class MainActivity extends AppCompatActivity {
    private WebView web;
    private PermissionRequest pending;

    /** الجسر بين الواجهة والسيرفر الداخلي */
    public class Bridge {
        @JavascriptInterface
        public String start(String user, String pass) {
            String err = ChatServer.start(getApplicationContext(), user, pass);
            if (err != null) return "{\"ok\":false,\"err\":" + JSONObject.quote(err) + "}";
            ContextCompat.startForegroundService(MainActivity.this, new Intent(MainActivity.this, ChatService.class));
            return "{\"ok\":true}";
        }

        @JavascriptInterface
        public void stop() {
            ChatServer.shutdown();
            stopService(new Intent(MainActivity.this, ChatService.class));
        }

        @JavascriptInterface
        public String info() {
            return "{\"running\":" + ChatServer.running() + ",\"port\":" + ChatServer.PORT
                    + ",\"ips\":" + new JSONArray(ChatServer.ips()).toString() + "}";
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        web = new WebView(this);
        setContentView(web);

        if (Build.VERSION.SDK_INT >= 33
                && ContextCompat.checkSelfPermission(this, "android.permission.POST_NOTIFICATIONS") != PackageManager.PERMISSION_GRANTED) {
            ActivityCompat.requestPermissions(this, new String[]{"android.permission.POST_NOTIFICATIONS"}, 2);
        }

        WebSettings s = web.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);
        s.setMediaPlaybackRequiresUserGesture(false);
        s.setMixedContentMode(WebSettings.MIXED_CONTENT_ALWAYS_ALLOW);

        web.addJavascriptInterface(new Bridge(), "AndroidBridge");
        web.setWebViewClient(new WebViewClient());
        web.setWebChromeClient(new WebChromeClient() {
            @Override
            public void onPermissionRequest(final PermissionRequest request) {
                runOnUiThread(() -> {
                    if (ContextCompat.checkSelfPermission(MainActivity.this, Manifest.permission.RECORD_AUDIO)
                            == PackageManager.PERMISSION_GRANTED) {
                        request.grant(request.getResources());
                    } else {
                        pending = request;
                        ActivityCompat.requestPermissions(MainActivity.this,
                                new String[]{Manifest.permission.RECORD_AUDIO}, 1);
                    }
                });
            }
        });
        web.loadUrl("file:///android_asset/index.html");
    }

    @Override
    public void onRequestPermissionsResult(int code, String[] perms, int[] results) {
        super.onRequestPermissionsResult(code, perms, results);
        if (code == 1 && pending != null) {
            if (results.length > 0 && results[0] == PackageManager.PERMISSION_GRANTED) {
                pending.grant(pending.getResources());
            } else {
                pending.deny();
            }
            pending = null;
        }
    }

    @Override
    public void onBackPressed() {
        web.evaluateJavascript("window.goBack?window.goBack():false", v -> {
            if (!"true".equals(v)) finish();
        });
    }
}

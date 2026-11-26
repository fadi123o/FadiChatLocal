package com.fadi.localchat;

import android.Manifest;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.util.Base64;
import android.webkit.JavascriptInterface;
import android.webkit.PermissionRequest;
import android.webkit.ValueCallback;
import android.webkit.WebChromeClient;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.Collections;
import java.util.ArrayList;
import java.util.List;

public class MainActivity extends AppCompatActivity {
    private WebView web;
    private PermissionRequest pending;
    private ValueCallback<Uri[]> filePathCb;

    private final ActivityResultLauncher<Intent> picker = registerForActivityResult(
            new ActivityResultContracts.StartActivityForResult(), result -> {
                if (filePathCb != null) {
                    filePathCb.onReceiveValue(
                            WebChromeClient.FileChooserParams.parseResult(result.getResultCode(), result.getData()));
                    filePathCb = null;
                }
            });

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

        @JavascriptInterface
        public void scan() {
            Discovery.scan(ChatServer.PORT);
        }

        @JavascriptInterface
        public String scanResult() {
            return Discovery.result();
        }

        @JavascriptInterface
        public String ts() {
            String ip = "";
            boolean inst = true;
            try {
                for (NetworkInterface ni : Collections.list(NetworkInterface.getNetworkInterfaces()))
                    for (InetAddress a : Collections.list(ni.getInetAddresses())) {
                        byte[] b = a.getAddress();
                        if (a instanceof Inet4Address && (b[0] & 255) == 100 && (b[1] & 192) == 64) ip = a.getHostAddress();
                    }
            } catch (Exception ignored) { }
            try { getPackageManager().getPackageInfo("com.tailscale.ipn", 0); } catch (Exception e) { inst = false; }
            return "{\"on\":" + !ip.isEmpty() + ",\"inst\":" + inst + ",\"ip\":\"" + ip + "\"}";
        }

        @JavascriptInterface
        public void openTs() {
            Intent i = getPackageManager().getLaunchIntentForPackage("com.tailscale.ipn");
            if (i == null) i = new Intent(Intent.ACTION_VIEW, Uri.parse("https://play.google.com/store/apps/details?id=com.tailscale.ipn"));
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            try { startActivity(i); } catch (Exception ignored) { }
        }

        @JavascriptInterface
        public String saveFile(String name, String mime, String b64) {
            try {
                File dir = getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS);
                if (dir == null) dir = getFilesDir();
                dir.mkdirs();
                String safe = name.replaceAll("[\\\\/:*?\"<>|]", "_");
                if (safe.isEmpty()) safe = "file";
                File f = new File(dir, safe);
                int i = 1;
                while (f.exists()) {
                    f = new File(dir, i + "_" + safe);
                    i++;
                }
                FileOutputStream o = new FileOutputStream(f);
                o.write(Base64.decode(b64, Base64.DEFAULT));
                o.close();
                return f.getAbsolutePath();
            } catch (Exception e) {
                return "";
            }
        }
    }

    private boolean has(String perm) {
        return ContextCompat.checkSelfPermission(this, perm) == PackageManager.PERMISSION_GRANTED;
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        web = new WebView(this);
        setContentView(web);

        if (Build.VERSION.SDK_INT >= 33 && !has("android.permission.POST_NOTIFICATIONS")) {
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
                    List<String> need = new ArrayList<String>();
                    for (String r : request.getResources()) {
                        if (PermissionRequest.RESOURCE_AUDIO_CAPTURE.equals(r) && !has(Manifest.permission.RECORD_AUDIO))
                            need.add(Manifest.permission.RECORD_AUDIO);
                        if (PermissionRequest.RESOURCE_VIDEO_CAPTURE.equals(r) && !has(Manifest.permission.CAMERA))
                            need.add(Manifest.permission.CAMERA);
                    }
                    if (need.isEmpty()) {
                        request.grant(request.getResources());
                    } else {
                        pending = request;
                        ActivityCompat.requestPermissions(MainActivity.this, need.toArray(new String[0]), 1);
                    }
                });
            }

            @Override
            public boolean onShowFileChooser(WebView w, ValueCallback<Uri[]> cb, FileChooserParams p) {
                if (filePathCb != null) filePathCb.onReceiveValue(null);
                filePathCb = cb;
                try {
                    picker.launch(p.createIntent());
                } catch (Exception e) {
                    filePathCb = null;
                    return false;
                }
                return true;
            }
        });
        web.loadUrl("file:///android_asset/index.html");
    }

    @Override
    public void onRequestPermissionsResult(int code, String[] perms, int[] results) {
        super.onRequestPermissionsResult(code, perms, results);
        if (code == 1 && pending != null) {
            boolean ok = results.length > 0;
            for (int r : results) if (r != PackageManager.PERMISSION_GRANTED) ok = false;
            if (ok) pending.grant(pending.getResources()); else pending.deny();
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

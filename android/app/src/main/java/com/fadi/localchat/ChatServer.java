package com.fadi.localchat;

import android.content.Context;
import android.util.Base64;

import org.java_websocket.WebSocket;
import org.java_websocket.handshake.ClientHandshake;
import org.java_websocket.server.WebSocketServer;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/** سيرفر الدردشة الداخلي — تصميم: المهندس فادي العفاره */
public class ChatServer extends WebSocketServer {
    public static final int PORT = 8080;
    private static ChatServer inst;
    private static final SecureRandom RND = new SecureRandom();
    private static final List<String> CALL_OPS = Arrays.asList("offer", "answer", "ice", "end", "reject", "busy");

    static class User {
        String name, salt, hash;
        boolean admin, banned;
        List<String> contacts = new ArrayList<String>();
        List<String> blocked = new ArrayList<String>();
    }

    static class Msg {
        String id, f, to, k, x, v;
        int d;
        long ts;
    }

    private final Object lock = new Object();
    private final File dbFile, voiceDir;
    private final Map<String, User> users = new LinkedHashMap<String, User>();
    private final List<Msg> msgs = new ArrayList<Msg>();
    private final Map<WebSocket, String> sessions = new HashMap<WebSocket, String>();
    private final Map<String, long[]> fails = new HashMap<String, long[]>();
    private final ScheduledExecutorService ex = Executors.newSingleThreadScheduledExecutor();
    private final CountDownLatch latch = new CountDownLatch(1);
    private volatile String startError;
    private boolean savePending;

    private ChatServer(File dir, String adminUser, String adminPass) {
        super(new InetSocketAddress(PORT));
        dbFile = new File(dir, "db.json");
        voiceDir = new File(dir, "voice");
        voiceDir.mkdirs();
        load();
        if (users.isEmpty() && okName(adminUser) && okPass(adminPass)) {
            users.put(adminUser, newUser(adminUser, adminPass, true));
            writeDb();
        }
    }

    // ================= واجهة التحكم (تُستدعى من الجسر) =================
    public static synchronized String start(Context ctx, String adminUser, String adminPass) {
        if (inst != null) return null;
        try {
            ChatServer s = new ChatServer(ctx.getFilesDir(), adminUser, adminPass);
            if (s.users.isEmpty()) {
                s.ex.shutdown();
                return "بيانات المدير غير صالحة (الاسم 2-20 حرفاً، وكلمة السر 4 أحرف على الأقل)";
            }
            s.setReuseAddr(true);
            s.setConnectionLostTimeout(30);
            s.start();
            if (!s.latch.await(4, TimeUnit.SECONDS)) {
                s.quiet();
                return "انتهت مهلة تشغيل السيرفر";
            }
            if (s.startError != null) {
                s.quiet();
                return "تعذر فتح المنفذ " + PORT + ": " + s.startError;
            }
            inst = s;
            return null;
        } catch (Exception e) {
            return String.valueOf(e.getMessage());
        }
    }

    public static synchronized void shutdown() {
        if (inst == null) return;
        ChatServer s = inst;
        inst = null;
        synchronized (s.lock) {
            s.writeDb();
        }
        s.quiet();
    }

    public static boolean running() {
        return inst != null;
    }

    public static List<String> ips() {
        List<String> wifi = new ArrayList<String>();
        List<String> other = new ArrayList<String>();
        try {
            for (NetworkInterface ni : Collections.list(NetworkInterface.getNetworkInterfaces())) {
                if (!ni.isUp() || ni.isLoopback()) continue;
                String nm = ni.getName();
                boolean lan = nm.startsWith("wlan") || nm.startsWith("ap") || nm.startsWith("swlan") || nm.startsWith("eth");
                for (InetAddress a : Collections.list(ni.getInetAddresses())) {
                    if (a instanceof Inet4Address && !a.isLoopbackAddress()) {
                        if (lan) wifi.add(a.getHostAddress()); else other.add(a.getHostAddress());
                    }
                }
            }
        } catch (Exception ignored) {
        }
        return wifi.isEmpty() ? other : wifi;
    }

    private void quiet() {
        try {
            stop(300);
        } catch (Exception ignored) {
        }
        ex.shutdown();
    }

    // ================= أدوات =================
    private static String rnd(int n) {
        byte[] b = new byte[n];
        RND.nextBytes(b);
        StringBuilder s = new StringBuilder();
        for (byte x : b) s.append(String.format("%02x", x));
        return s.toString();
    }

    private static String hash(String pass, String salt) {
        try {
            SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            byte[] h = f.generateSecret(new PBEKeySpec(pass.toCharArray(), salt.getBytes(StandardCharsets.UTF_8), 5000, 160)).getEncoded();
            return Base64.encodeToString(h, Base64.NO_WRAP);
        } catch (Exception e) {
            return "";
        }
    }

    private static boolean eq(String a, String b) {
        if (a.isEmpty() || b == null) return false;
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }

    private static boolean okName(String n) {
        return n != null && n.matches("[\\w\\x{0600}-\\x{06FF}.\\-]{2,20}");
    }

    private static boolean okPass(String p) {
        return p != null && p.length() >= 4 && p.length() <= 64;
    }

    private static User newUser(String name, String pass, boolean admin) {
        User u = new User();
        u.name = name;
        u.admin = admin;
        setPass(u, pass);
        return u;
    }

    private static void setPass(User u, String pass) {
        u.salt = rnd(8);
        u.hash = hash(pass, u.salt);
    }

    private static JSONObject J(Object... kv) {
        JSONObject o = new JSONObject();
        try {
            for (int i = 0; i + 1 < kv.length; i += 2) o.put((String) kv[i], kv[i + 1]);
        } catch (Exception ignored) {
        }
        return o;
    }

    private static JSONArray arr(List<String> l) {
        JSONArray a = new JSONArray();
        for (String s : l) a.put(s);
        return a;
    }

    private static List<String> strs(JSONArray a) {
        List<String> l = new ArrayList<String>();
        if (a != null) for (int i = 0; i < a.length(); i++) l.add(a.optString(i));
        return l;
    }

    private static JSONObject mj(Msg g) {
        return J("id", g.id, "f", g.f, "to", g.to, "k", g.k, "ts", g.ts, "x", g.x, "v", g.v, "d", g.d);
    }

    // ================= التخزين =================
    private void load() {
        try {
            if (!dbFile.exists()) return;
            byte[] b = new byte[(int) dbFile.length()];
            DataInputStream d = new DataInputStream(new FileInputStream(dbFile));
            d.readFully(b);
            d.close();
            JSONObject o = new JSONObject(new String(b, StandardCharsets.UTF_8));
            JSONArray ua = o.optJSONArray("users");
            if (ua != null) {
                for (int i = 0; i < ua.length(); i++) {
                    JSONObject j = ua.getJSONObject(i);
                    User u = new User();
                    u.name = j.getString("name");
                    u.salt = j.getString("salt");
                    u.hash = j.getString("hash");
                    u.admin = j.optBoolean("admin");
                    u.banned = j.optBoolean("banned");
                    u.contacts = strs(j.optJSONArray("contacts"));
                    u.blocked = strs(j.optJSONArray("blocked"));
                    users.put(u.name, u);
                }
            }
            JSONArray ma = o.optJSONArray("msgs");
            if (ma != null) {
                for (int i = 0; i < ma.length(); i++) {
                    JSONObject j = ma.getJSONObject(i);
                    Msg g = new Msg();
                    g.id = j.optString("id");
                    g.f = j.optString("f");
                    g.to = j.optString("to");
                    g.k = j.optString("k", "text");
                    g.ts = j.optLong("ts");
                    g.x = j.has("x") ? j.optString("x") : null;
                    g.v = j.has("v") ? j.optString("v") : null;
                    g.d = j.optInt("d");
                    msgs.add(g);
                }
            }
        } catch (Exception ignored) {
        }
    }

    private void writeDb() {
        try {
            JSONArray ua = new JSONArray();
            for (User u : users.values()) {
                ua.put(J("name", u.name, "salt", u.salt, "hash", u.hash, "admin", u.admin, "banned", u.banned,
                        "contacts", arr(u.contacts), "blocked", arr(u.blocked)));
            }
            JSONArray ma = new JSONArray();
            for (Msg g : msgs) ma.put(mj(g));
            File tmp = new File(dbFile.getParentFile(), "db.tmp");
            FileOutputStream fo = new FileOutputStream(tmp);
            fo.write(J("users", ua, "msgs", ma).toString().getBytes(StandardCharsets.UTF_8));
            fo.close();
            tmp.renameTo(dbFile);
        } catch (Exception ignored) {
        }
    }

    private void save() {
        if (savePending) return;
        savePending = true;
        try {
            ex.schedule(new Runnable() {
                @Override
                public void run() {
                    synchronized (lock) {
                        savePending = false;
                        writeDb();
                    }
                }
            }, 500, TimeUnit.MILLISECONDS);
        } catch (Exception e) {
            savePending = false;
        }
    }

    // ================= الإرسال =================
    private void send(WebSocket c, JSONObject o) {
        try {
            if (c.isOpen()) c.send(o.toString());
        } catch (Exception ignored) {
        }
    }

    private void err(WebSocket c, String m) {
        send(c, J("t", "err", "m", m));
    }

    private void tell(String name, JSONObject o) {
        for (Map.Entry<WebSocket, String> e : new ArrayList<Map.Entry<WebSocket, String>>(sessions.entrySet())) {
            if (e.getValue().equals(name)) send(e.getKey(), o);
        }
    }

    private void all(JSONObject o) {
        for (WebSocket c : new ArrayList<WebSocket>(sessions.keySet())) send(c, o);
    }

    private boolean online(String n) {
        return sessions.containsValue(n);
    }

    private boolean isAdm(String n) {
        User u = users.get(n);
        return u != null && u.admin;
    }

    private JSONArray dirFor(boolean adm) {
        JSONArray a = new JSONArray();
        for (User u : users.values()) {
            if (adm) a.put(J("n", u.name, "o", online(u.name), "a", u.admin, "b", u.banned));
            else a.put(J("n", u.name, "o", online(u.name), "a", u.admin));
        }
        return a;
    }

    private JSONObject meOf(String n) {
        User u = users.get(n);
        return J("n", n, "admin", u.admin, "contacts", arr(u.contacts), "blocked", arr(u.blocked));
    }

    private JSONArray hist(String n) {
        List<JSONObject> out = new ArrayList<JSONObject>();
        for (int i = msgs.size() - 1; i >= 0 && out.size() < 500; i--) {
            Msg g = msgs.get(i);
            if (g.to.equals("*") || g.f.equals(n) || g.to.equals(n)) out.add(mj(g));
        }
        JSONArray a = new JSONArray();
        for (int i = out.size() - 1; i >= 0; i--) a.put(out.get(i));
        return a;
    }

    private JSONObject initOf(String n) {
        JSONArray ice = new JSONArray();
        ice.put(J("urls", "stun:stun.l.google.com:19302"));
        return J("t", "init", "me", meOf(n), "ice", ice, "dir", dirFor(isAdm(n)), "msgs", hist(n));
    }

    private void pushDir() {
        for (Map.Entry<WebSocket, String> e : new ArrayList<Map.Entry<WebSocket, String>>(sessions.entrySet())) {
            send(e.getKey(), J("t", "dir", "d", dirFor(isAdm(e.getValue()))));
        }
    }

    private void reinit() {
        for (Map.Entry<WebSocket, String> e : new ArrayList<Map.Entry<WebSocket, String>>(sessions.entrySet())) {
            if (users.containsKey(e.getValue())) send(e.getKey(), initOf(e.getValue()));
        }
    }

    private void kick(String n, String m) {
        for (Map.Entry<WebSocket, String> e : new ArrayList<Map.Entry<WebSocket, String>>(sessions.entrySet())) {
            if (e.getValue().equals(n)) {
                send(e.getKey(), J("t", "kick", "m", m));
                e.getKey().close();
            }
        }
    }

    // ================= أحداث WebSocket =================
    @Override
    public void onOpen(WebSocket c, ClientHandshake h) {
    }

    @Override
    public void onStart() {
        latch.countDown();
    }

    @Override
    public void onError(WebSocket c, Exception e) {
        if (c == null) {
            startError = e.getMessage() == null ? "error" : e.getMessage();
            latch.countDown();
        }
    }

    @Override
    public void onClose(WebSocket c, int code, String reason, boolean remote) {
        synchronized (lock) {
            if (sessions.remove(c) != null) pushDir();
        }
    }

    @Override
    public void onMessage(WebSocket c, String message) {
        synchronized (lock) {
            try {
                JSONObject m = new JSONObject(message);
                if (!sessions.containsKey(c)) auth(c, m); else handle(c, m);
            } catch (Exception ignored) {
            }
        }
    }

    private void auth(WebSocket c, JSONObject m) {
        if (!"auth".equals(m.optString("t"))) return;
        String ip = "?";
        try {
            ip = c.getRemoteSocketAddress().getAddress().getHostAddress();
        } catch (Exception ignored) {
        }
        long now = System.currentTimeMillis();
        long[] f = fails.get(ip);
        if (f != null && f[0] >= 5 && now - f[1] < 300000) {
            send(c, J("t", "fail", "m", "محاولات كثيرة، انتظر 5 دقائق"));
            return;
        }
        String name = m.optString("u", "").trim();
        User u = users.get(name);
        if (u == null || !eq(hash(m.optString("p", ""), u.salt), u.hash)) {
            if (f == null || now - f[1] >= 300000) f = new long[]{0, now};
            f[0]++;
            f[1] = now;
            fails.put(ip, f);
            send(c, J("t", "fail", "m", "اسم المستخدم أو كلمة السر غير صحيحة"));
            return;
        }
        if (u.banned) {
            send(c, J("t", "fail", "m", "هذا الحساب محظور"));
            return;
        }
        fails.remove(ip);
        sessions.put(c, name);
        send(c, initOf(name));
        pushDir();
    }

    private void handle(WebSocket c, JSONObject m) throws Exception {
        String n = sessions.get(c);
        User u = users.get(n);
        if (u == null) return;
        String t = m.optString("t");
        if (t.equals("msg")) onMsg(c, n, u, m);
        else if (t.equals("contact") || t.equals("block")) onList(c, n, u, m, t.equals("contact"));
        else if (t.equals("call")) onCall(c, n, u, m);
        else if (t.equals("vget")) onVoice(c, n, m);
        else if (t.equals("adm") && u.admin) admin(c, n, m);
    }

    private void onMsg(WebSocket c, String n, User u, JSONObject m) throws Exception {
        String to = m.optString("to", "");
        boolean pub = to.equals("*");
        if (!pub) {
            User r = users.get(to);
            if (r == null) { err(c, "المستخدم غير موجود"); return; }
            if (u.blocked.contains(to) || r.blocked.contains(n) || r.banned) { err(c, "لا يمكن مراسلة هذا المستخدم"); return; }
        }
        Msg g = new Msg();
        g.id = rnd(6);
        g.f = n;
        g.to = to;
        g.k = "text";
        g.ts = System.currentTimeMillis();
        if ("voice".equals(m.optString("k"))) {
            String data = m.optString("data", "");
            if (data.isEmpty() || data.length() > 2500000) { err(c, "التسجيل كبير جداً"); return; }
            String mime = m.optString("mime", "");
            String ext = (mime.contains("mp4") || mime.contains("aac")) ? "m4a" : "webm";
            String id = rnd(8) + "." + ext;
            FileOutputStream fo = new FileOutputStream(new File(voiceDir, id));
            fo.write(Base64.decode(data, Base64.DEFAULT));
            fo.close();
            g.k = "voice";
            g.v = id;
            g.d = Math.min(Math.max(m.optInt("d", 0), 0), 300);
        } else {
            String x = m.optString("x", "").trim();
            if (x.isEmpty()) return;
            g.x = x.length() > 2000 ? x.substring(0, 2000) : x;
        }
        msgs.add(g);
        while (msgs.size() > 5000) msgs.remove(0);
        save();
        JSONObject o = J("t", "msg", "m", mj(g));
        if (pub) all(o);
        else {
            tell(n, o);
            if (!to.equals(n)) tell(to, o);
        }
    }

    private void onList(WebSocket c, String n, User u, JSONObject m, boolean contacts) {
        String name = m.optString("name", "");
        List<String> list = contacts ? u.contacts : u.blocked;
        if ("add".equals(m.optString("op"))) {
            if (!users.containsKey(name) || name.equals(n)) { err(c, "المستخدم غير موجود"); return; }
            if (!list.contains(name)) list.add(name);
        } else {
            list.remove(name);
        }
        save();
        JSONObject me = meOf(n);
        try {
            me.put("t", "me");
        } catch (Exception ignored) {
        }
        tell(n, me);
    }

    private void onCall(WebSocket c, String n, User u, JSONObject m) {
        String r = m.optString("to", "");
        String op = m.optString("op", "");
        User ru = users.get(r);
        if (ru == null || r.equals(n) || !CALL_OPS.contains(op)) return;
        boolean offer = op.equals("offer");
        if (ru.blocked.contains(n) || u.blocked.contains(r)) {
            if (offer) send(c, J("t", "call", "from", r, "op", "reject"));
            return;
        }
        if (!online(r)) {
            if (offer) send(c, J("t", "call", "from", r, "op", "unavail"));
            return;
        }
        tell(r, J("t", "call", "from", n, "op", op, "data", m.opt("data")));
    }

    private void onVoice(WebSocket c, String n, JSONObject m) throws Exception {
        String id = m.optString("v", "");
        if (!id.matches("[a-f0-9]{16}\\.(webm|m4a)")) return;
        boolean ok = false;
        for (Msg g : msgs) {
            if (id.equals(g.v) && (g.to.equals("*") || g.f.equals(n) || g.to.equals(n))) { ok = true; break; }
        }
        if (!ok) return;
        File f = new File(voiceDir, id);
        if (!f.exists()) { err(c, "الملف الصوتي غير موجود"); return; }
        byte[] b = new byte[(int) f.length()];
        DataInputStream di = new DataInputStream(new FileInputStream(f));
        di.readFully(b);
        di.close();
        send(c, J("t", "vdata", "v", id, "data", Base64.encodeToString(b, Base64.NO_WRAP),
                "mime", id.endsWith("m4a") ? "audio/mp4" : "audio/webm"));
    }

    // ================= الإدارة =================
    private void rename(String o, String n) {
        User u = users.remove(o);
        u.name = n;
        users.put(n, u);
        for (User x : users.values()) {
            for (int i = 0; i < x.contacts.size(); i++) if (x.contacts.get(i).equals(o)) x.contacts.set(i, n);
            for (int i = 0; i < x.blocked.size(); i++) if (x.blocked.get(i).equals(o)) x.blocked.set(i, n);
        }
        for (Msg g : msgs) {
            if (g.f.equals(o)) g.f = n;
            if (g.to.equals(o)) g.to = n;
        }
        for (Map.Entry<WebSocket, String> e : sessions.entrySet()) {
            if (e.getValue().equals(o)) e.setValue(n);
        }
    }

    private void admin(WebSocket c, String me, JSONObject m) {
        String op = m.optString("op", "");
        String N = m.optString("name", "").trim();
        String pass = m.optString("pass", "");
        User t = users.get(N);
        if (op.equals("add")) {
            if (!okName(N) || !okPass(pass)) { err(c, "الاسم 2-20 حرفاً وكلمة السر 4 أحرف على الأقل"); return; }
            if (t != null) { err(c, "الاسم مستخدم مسبقاً"); return; }
            users.put(N, newUser(N, pass, false));
        } else if (op.equals("pass")) {
            if (t == null || !okPass(pass)) { err(c, "بيانات غير صالحة"); return; }
            setPass(t, pass);
        } else if (op.equals("ban") || op.equals("unban")) {
            if (t == null || N.equals(me)) return;
            t.banned = op.equals("ban");
            if (t.banned) kick(N, "تم حظر حسابك");
        } else if (op.equals("del")) {
            if (t == null || N.equals(me)) return;
            kick(N, "تم حذف حسابك");
            users.remove(N);
            Iterator<Msg> it = msgs.iterator();
            while (it.hasNext()) {
                Msg g = it.next();
                if (!g.to.equals("*") && (g.f.equals(N) || g.to.equals(N))) it.remove();
            }
            for (User x : users.values()) {
                x.contacts.remove(N);
                x.blocked.remove(N);
            }
        } else if (op.equals("creds")) {
            if (!okName(N) || (!pass.isEmpty() && !okPass(pass))) { err(c, "بيانات غير صالحة"); return; }
            if (!N.equals(me)) {
                if (users.containsKey(N)) { err(c, "الاسم مستخدم مسبقاً"); return; }
                rename(me, N);
            }
            if (!pass.isEmpty()) setPass(users.get(N), pass);
        } else {
            return;
        }
        save();
        reinit();
        send(c, J("t", "ok", "m", "تم الحفظ ✔"));
    }
}

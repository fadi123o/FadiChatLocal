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
    private static final int MAX_B64 = 8500000; // ~6MB ملف
    private static ChatServer inst;
    private static final SecureRandom RND = new SecureRandom();
    private static final List<String> CALL_OPS = Arrays.asList("offer", "answer", "ice", "end", "reject", "busy");
    private static final List<String> MEDIA = Arrays.asList("voice", "img", "vid", "file");

    static class User {
        String name, salt, hash, fid;
        boolean admin, banned;
        List<String> contacts = new ArrayList<String>();
        List<String> blocked = new ArrayList<String>();
    }

    static class Msg {
        String id, f, to, k, x, v, n, mime;
        int d;
        long ts, z;
    }

    static class Group {
        String id, name, owner;
        List<String> members = new ArrayList<String>();
    }

    static class Req {
        String name, salt, hash;
        long ts;
    }

    private final Object lock = new Object();
    private final File dbFile, voiceDir;
    private final Map<String, User> users = new LinkedHashMap<String, User>();
    private final List<Msg> msgs = new ArrayList<Msg>();
    private final Map<String, Group> groups = new LinkedHashMap<String, Group>();
    private final Map<String, Req> reqs = new LinkedHashMap<String, Req>();
    private final Map<String, WebSocket> waiting = new HashMap<String, WebSocket>();
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
            User a = newUser(adminUser, adminPass, true);
            a.fid = newFid();
            users.put(adminUser, a);
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
            Discovery.startResponder(s.serverName(), PORT);
            return null;
        } catch (Exception e) {
            return String.valueOf(e.getMessage());
        }
    }

    public static synchronized void shutdown() {
        Discovery.stopResponder();
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

    private String serverName() {
        for (User u : users.values()) if (u.admin) return u.name;
        return "Fadi Chat";
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

    private static boolean okCode(String p) {
        return p != null && p.matches("\\d{6}");
    }

    private String newFid() {
        while (true) {
            String f = String.valueOf(100000 + RND.nextInt(900000));
            boolean used = false;
            for (User u : users.values()) if (f.equals(u.fid)) used = true;
            if (!used) return f;
        }
    }

    private String resolve(String x) {
        if (users.containsKey(x)) return x;
        if (okCode(x)) for (User u : users.values()) if (x.equals(u.fid)) return u.name;
        return null;
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

    static JSONObject J(Object... kv) {
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
        return J("id", g.id, "f", g.f, "to", g.to, "k", g.k, "ts", g.ts, "x", g.x, "v", g.v, "d", g.d,
                "n", g.n, "mime", g.mime, "z", g.z);
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
                    u.fid = j.optString("fid", "");
                    u.admin = j.optBoolean("admin");
                    u.banned = j.optBoolean("banned");
                    u.contacts = strs(j.optJSONArray("contacts"));
                    u.blocked = strs(j.optJSONArray("blocked"));
                    users.put(u.name, u);
                }
                for (User u : users.values()) if (u.fid == null || u.fid.isEmpty()) u.fid = newFid();
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
                    g.n = j.has("n") ? j.optString("n") : null;
                    g.mime = j.has("mime") ? j.optString("mime") : null;
                    g.d = j.optInt("d");
                    g.z = j.optLong("z");
                    msgs.add(g);
                }
            }
            JSONArray ga = o.optJSONArray("groups");
            if (ga != null) {
                for (int i = 0; i < ga.length(); i++) {
                    JSONObject j = ga.getJSONObject(i);
                    Group g = new Group();
                    g.id = j.getString("id");
                    g.name = j.getString("name");
                    g.owner = j.getString("owner");
                    g.members = strs(j.optJSONArray("members"));
                    groups.put(g.id, g);
                }
            }
            JSONArray ra = o.optJSONArray("reqs");
            if (ra != null) {
                for (int i = 0; i < ra.length(); i++) {
                    JSONObject j = ra.getJSONObject(i);
                    Req r = new Req();
                    r.name = j.getString("name");
                    r.salt = j.getString("salt");
                    r.hash = j.getString("hash");
                    r.ts = j.optLong("ts");
                    reqs.put(r.name, r);
                }
            }
        } catch (Exception ignored) {
        }
    }

    private void writeDb() {
        try {
            JSONArray ua = new JSONArray();
            for (User u : users.values()) {
                ua.put(J("name", u.name, "salt", u.salt, "hash", u.hash, "fid", u.fid, "admin", u.admin, "banned", u.banned,
                        "contacts", arr(u.contacts), "blocked", arr(u.blocked)));
            }
            JSONArray ma = new JSONArray();
            for (Msg g : msgs) ma.put(mj(g));
            JSONArray ga = new JSONArray();
            for (Group g : groups.values()) ga.put(J("id", g.id, "name", g.name, "owner", g.owner, "members", arr(g.members)));
            JSONArray ra = new JSONArray();
            for (Req r : reqs.values()) ra.put(J("name", r.name, "salt", r.salt, "hash", r.hash, "ts", r.ts));
            File tmp = new File(dbFile.getParentFile(), "db.tmp");
            FileOutputStream fo = new FileOutputStream(tmp);
            fo.write(J("users", ua, "msgs", ma, "groups", ga, "reqs", ra).toString().getBytes(StandardCharsets.UTF_8));
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

    private boolean canSee(String n, Msg g) {
        if (g.to.equals("*") || g.f.equals(n) || g.to.equals(n)) return true;
        Group gr = groups.get(g.to);
        return gr != null && gr.members.contains(n);
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
        return J("n", n, "admin", u.admin, "fid", u.fid, "contacts", arr(u.contacts), "blocked", arr(u.blocked));
    }

    private JSONArray hist(String n) {
        List<JSONObject> out = new ArrayList<JSONObject>();
        for (int i = msgs.size() - 1; i >= 0 && out.size() < 500; i--) {
            Msg g = msgs.get(i);
            if (canSee(n, g)) out.add(mj(g));
        }
        JSONArray a = new JSONArray();
        for (int i = out.size() - 1; i >= 0; i--) a.put(out.get(i));
        return a;
    }

    private JSONArray groupsFor(String n) {
        JSONArray a = new JSONArray();
        for (Group g : groups.values()) {
            if (g.members.contains(n)) a.put(J("id", g.id, "n", g.name, "o", g.owner, "m", arr(g.members)));
        }
        return a;
    }

    private JSONArray reqsArr() {
        JSONArray a = new JSONArray();
        for (Req r : reqs.values()) a.put(J("n", r.name, "ts", r.ts));
        return a;
    }

    private JSONObject initOf(String n) {
        JSONArray ice = new JSONArray();
        ice.put(J("urls", "stun:stun.l.google.com:19302"));
        return J("t", "init", "me", meOf(n), "ice", ice, "dir", dirFor(isAdm(n)), "msgs", hist(n),
                "groups", groupsFor(n), "reqs", isAdm(n) ? reqsArr() : new JSONArray());
    }

    private void pushDir() {
        for (Map.Entry<WebSocket, String> e : new ArrayList<Map.Entry<WebSocket, String>>(sessions.entrySet())) {
            send(e.getKey(), J("t", "dir", "d", dirFor(isAdm(e.getValue()))));
        }
    }

    private void pushGroups() {
        for (Map.Entry<WebSocket, String> e : new ArrayList<Map.Entry<WebSocket, String>>(sessions.entrySet())) {
            send(e.getKey(), J("t", "groups", "g", groupsFor(e.getValue())));
        }
    }

    private void pushReqs() {
        for (Map.Entry<WebSocket, String> e : new ArrayList<Map.Entry<WebSocket, String>>(sessions.entrySet())) {
            if (isAdm(e.getValue())) send(e.getKey(), J("t", "reqs", "r", reqsArr()));
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

    private boolean limited(String key) {
        long[] f = fails.get(key);
        return f != null && f[0] >= 5 && System.currentTimeMillis() - f[1] < 300000;
    }

    private void bump(String key) {
        long now = System.currentTimeMillis();
        long[] f = fails.get(key);
        if (f == null || now - f[1] >= 300000) f = new long[]{0, now};
        f[0]++;
        f[1] = now;
        fails.put(key, f);
    }

    private static String ipOf(WebSocket c) {
        try {
            return c.getRemoteSocketAddress().getAddress().getHostAddress();
        } catch (Exception e) {
            return "?";
        }
    }

    private void delFile(Msg g) {
        if (g.v != null) new File(voiceDir, g.v).delete();
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
            waiting.values().remove(c);
            if (sessions.remove(c) != null) pushDir();
        }
    }

    @Override
    public void onMessage(WebSocket c, String message) {
        synchronized (lock) {
            try {
                JSONObject m = new JSONObject(message);
                if (sessions.containsKey(c)) {
                    handle(c, m);
                } else {
                    String t = m.optString("t");
                    if (t.equals("join")) join(c, m);
                    else if (t.equals("cancel")) cancel(c);
                    else auth(c, m);
                }
            } catch (Exception ignored) {
            }
        }
    }

    private void auth(WebSocket c, JSONObject m) {
        if (!"auth".equals(m.optString("t"))) return;
        String ip = ipOf(c);
        if (limited(ip)) {
            send(c, J("t", "fail", "m", "محاولات كثيرة، انتظر 5 دقائق"));
            return;
        }
        String name = m.optString("u", "").trim();
        User u = users.get(name);
        if (u == null || !eq(hash(m.optString("p", ""), u.salt), u.hash)) {
            bump(ip);
            send(c, J("t", "fail", "m", "اسم المستخدم أو الكود غير صحيح — إن كنت جديداً اضغط «طلب انضمام»"));
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

    /** طلب انضمام: اسم + كود من 6 أرقام، ينتظر موافقة المدير */
    private void join(WebSocket c, JSONObject m) {
        String key = "j" + ipOf(c);
        if (limited(key)) {
            send(c, J("t", "fail", "m", "طلبات كثيرة، انتظر 5 دقائق"));
            return;
        }
        String name = m.optString("u", "").trim();
        String code = m.optString("c", "");
        if (!okName(name) || !okCode(code)) {
            send(c, J("t", "fail", "m", "الاسم 2-20 حرفاً والكود 6 أرقام"));
            return;
        }
        if (users.containsKey(name)) {
            send(c, J("t", "fail", "m", "هذا الاسم مسجّل مسبقاً — استخدم زر الدخول"));
            return;
        }
        bump(key);
        Req r = new Req();
        r.name = name;
        r.ts = System.currentTimeMillis();
        r.salt = rnd(8);
        r.hash = hash(code, r.salt);
        reqs.put(name, r);
        waiting.put(name, c);
        save();
        send(c, J("t", "wait"));
        pushReqs();
    }

    private void cancel(WebSocket c) {
        for (Map.Entry<String, WebSocket> e : new ArrayList<Map.Entry<String, WebSocket>>(waiting.entrySet())) {
            if (e.getValue() == c) {
                reqs.remove(e.getKey());
                waiting.remove(e.getKey());
                save();
                pushReqs();
            }
        }
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
        else if (t.equals("grp")) onGroup(c, n, m);
        else if (t.equals("adm") && u.admin) admin(c, n, m);
    }

    private void onMsg(WebSocket c, String n, User u, JSONObject m) throws Exception {
        String to = m.optString("to", "");
        boolean pub = to.equals("*");
        boolean grp = to.startsWith("g:");
        if (grp) {
            Group gr = groups.get(to);
            if (gr == null || !gr.members.contains(n)) { err(c, "المجموعة غير موجودة"); return; }
        } else if (!pub) {
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
        String k = m.optString("k", "text");
        if (MEDIA.contains(k)) {
            String data = m.optString("data", "");
            if (data.isEmpty() || data.length() > MAX_B64) { err(c, "الملف كبير جداً (الحد 6 ميغابايت)"); return; }
            String mime = m.optString("mime", "application/octet-stream");
            if (mime.length() > 100) mime = mime.substring(0, 100);
            String ext = "bin";
            if (k.equals("voice")) ext = (mime.contains("mp4") || mime.contains("aac")) ? "m4a" : "webm";
            String id = rnd(8) + "." + ext;
            byte[] bytes = Base64.decode(data, Base64.DEFAULT);
            FileOutputStream fo = new FileOutputStream(new File(voiceDir, id));
            fo.write(bytes);
            fo.close();
            g.k = k;
            g.v = id;
            g.mime = mime;
            g.z = bytes.length;
            if (k.equals("voice")) {
                g.d = Math.min(Math.max(m.optInt("d", 0), 0), 300);
            } else {
                String nm = m.optString("n", "file").replaceAll("[\\\\/:*?\"<>|\\p{Cntrl}]", "_");
                if (nm.length() > 80) nm = nm.substring(0, 80);
                g.n = nm.isEmpty() ? "file" : nm;
            }
        } else {
            String x = m.optString("x", "").trim();
            if (x.isEmpty()) return;
            g.x = x.length() > 2000 ? x.substring(0, 2000) : x;
        }
        msgs.add(g);
        while (msgs.size() > 3000) delFile(msgs.remove(0));
        save();
        JSONObject o = J("t", "msg", "m", mj(g));
        if (pub) {
            all(o);
        } else if (grp) {
            for (String mem : new ArrayList<String>(groups.get(to).members)) tell(mem, o);
        } else {
            tell(n, o);
            if (!to.equals(n)) tell(to, o);
        }
    }

    private void onList(WebSocket c, String n, User u, JSONObject m, boolean contacts) {
        String name = m.optString("name", "").trim();
        List<String> list = contacts ? u.contacts : u.blocked;
        if ("add".equals(m.optString("op"))) {
            String r = resolve(name);
            if (r == null || r.equals(n)) { err(c, "المستخدم غير موجود"); return; }
            if (!list.contains(r)) list.add(r);
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
        if (!id.matches("[a-f0-9]{16}\\.(webm|m4a|bin)")) return;
        Msg found = null;
        for (Msg g : msgs) {
            if (id.equals(g.v) && canSee(n, g)) { found = g; break; }
        }
        File f = new File(voiceDir, id);
        if (found == null || !f.exists()) { send(c, J("t", "vdata", "v", id, "x", 1)); return; }
        byte[] b = new byte[(int) f.length()];
        DataInputStream di = new DataInputStream(new FileInputStream(f));
        di.readFully(b);
        di.close();
        String mime = (found.mime != null && !found.mime.isEmpty()) ? found.mime : (id.endsWith("m4a") ? "audio/mp4" : "audio/webm");
        send(c, J("t", "vdata", "v", id, "data", Base64.encodeToString(b, Base64.NO_WRAP), "mime", mime));
    }

    // ================= المجموعات =================
    private void dropMsgsOf(String to) {
        Iterator<Msg> it = msgs.iterator();
        while (it.hasNext()) {
            Msg g = it.next();
            if (g.to.equals(to)) { delFile(g); it.remove(); }
        }
    }

    private void leaveGroup(Group g, String n) {
        g.members.remove(n);
        if (g.members.isEmpty()) {
            groups.remove(g.id);
            dropMsgsOf(g.id);
        } else if (g.owner.equals(n)) {
            g.owner = g.members.get(0);
        }
    }

    private void onGroup(WebSocket c, String n, JSONObject m) {
        String op = m.optString("op", "");
        if (op.equals("new")) {
            String name = m.optString("name", "").trim();
            if (name.isEmpty() || name.length() > 30) { err(c, "اسم المجموعة غير صالح"); return; }
            Group g = new Group();
            g.id = "g:" + rnd(4);
            g.name = name;
            g.owner = n;
            g.members.add(n);
            JSONArray ms = m.optJSONArray("members");
            if (ms != null) {
                for (int i = 0; i < ms.length() && g.members.size() < 50; i++) {
                    String x = ms.optString(i);
                    if (users.containsKey(x) && !g.members.contains(x)) g.members.add(x);
                }
            }
            if (g.members.size() < 2) { err(c, "اختر عضواً واحداً على الأقل"); return; }
            groups.put(g.id, g);
        } else {
            Group g = groups.get(m.optString("id", ""));
            if (g == null || !g.members.contains(n)) return;
            String name = m.optString("name", "");
            boolean owner = g.owner.equals(n);
            if (op.equals("add") && owner) {
                if (users.containsKey(name) && !g.members.contains(name) && g.members.size() < 50) g.members.add(name);
            } else if (op.equals("rm") && owner && !name.equals(n)) {
                g.members.remove(name);
            } else if (op.equals("leave")) {
                leaveGroup(g, n);
            } else {
                return;
            }
        }
        save();
        pushGroups();
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
        for (Group g : groups.values()) {
            for (int i = 0; i < g.members.size(); i++) if (g.members.get(i).equals(o)) g.members.set(i, n);
            if (g.owner.equals(o)) g.owner = n;
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
            if (!okName(N) || !okCode(pass)) { err(c, "الاسم 2-20 حرفاً والكود 6 أرقام"); return; }
            if (t != null) { err(c, "الاسم مستخدم مسبقاً"); return; }
            User nu = newUser(N, pass, false);
            nu.fid = newFid();
            users.put(N, nu);
            reqs.remove(N);
        } else if (op.equals("accept")) {
            Req r = reqs.get(N);
            if (r == null) { err(c, "الطلب غير موجود"); return; }
            reqs.remove(N);
            if (t == null) {
                User nu = new User();
                nu.name = N;
                nu.salt = r.salt;
                nu.hash = r.hash;
                nu.fid = newFid();
                users.put(N, nu);
            }
            WebSocket w = waiting.remove(N);
            if (w != null) send(w, J("t", "accepted"));
        } else if (op.equals("reject")) {
            reqs.remove(N);
            WebSocket w = waiting.remove(N);
            if (w != null) send(w, J("t", "rejected"));
        } else if (op.equals("pass")) {
            if (t == null || !(t.admin ? okPass(pass) : okCode(pass))) { err(c, t != null && t.admin ? "كلمة السر 4 أحرف على الأقل" : "الكود يجب أن يكون 6 أرقام"); return; }
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
                if (!g.to.equals("*") && !g.to.startsWith("g:") && (g.f.equals(N) || g.to.equals(N))) { delFile(g); it.remove(); }
            }
            for (User x : users.values()) {
                x.contacts.remove(N);
                x.blocked.remove(N);
            }
            for (Group g : new ArrayList<Group>(groups.values())) {
                if (g.members.contains(N)) leaveGroup(g, N);
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

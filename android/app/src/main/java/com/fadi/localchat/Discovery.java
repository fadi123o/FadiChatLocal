package com.fadi.localchat;

import org.json.JSONArray;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** اكتشاف السيرفر تلقائياً على الشبكة المحلية (بث UDP + مسح منفذ السيرفر). */
final class Discovery {
    static final int UDP = 8081;
    private static final String Q = "FADICHAT?";
    private static final String A = "FADICHAT!";

    private static DatagramSocket responder;
    private static volatile boolean scanning = false;
    private static final Map<String, String> found = new LinkedHashMap<String, String>();

    private Discovery() { }

    // ---------- جهة السيرفر: يرد على سؤال "من هناك؟" ----------
    static synchronized void startResponder(final String name, final int port) {
        stopResponder();
        try {
            final DatagramSocket s = new DatagramSocket(null);
            s.setReuseAddress(true);
            s.bind(new InetSocketAddress(UDP));
            responder = s;
            Thread t = new Thread(new Runnable() {
                @Override
                public void run() {
                    byte[] buf = new byte[256];
                    while (!s.isClosed()) {
                        try {
                            DatagramPacket p = new DatagramPacket(buf, buf.length);
                            s.receive(p);
                            String q = new String(p.getData(), 0, p.getLength(), "UTF-8");
                            if (q.startsWith(Q)) {
                                byte[] r = (A + "|" + port + "|" + name).getBytes("UTF-8");
                                s.send(new DatagramPacket(r, r.length, p.getAddress(), p.getPort()));
                            }
                        } catch (Exception e) {
                            if (s.isClosed()) break;
                        }
                    }
                }
            });
            t.setDaemon(true);
            t.start();
        } catch (Exception e) {
            responder = null;
        }
    }

    static synchronized void stopResponder() {
        if (responder != null) {
            responder.close();
            responder = null;
        }
    }

    // ---------- جهة العميل: بحث ----------
    static synchronized void scan(final int tcpPort) {
        if (scanning) return;
        scanning = true;
        synchronized (found) {
            found.clear();
        }
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    doScan(tcpPort);
                } catch (Exception ignored) {
                } finally {
                    scanning = false;
                }
            }
        }).start();
    }

    private static void add(String ip, String name) {
        synchronized (found) {
            if (name.length() > 0 || !found.containsKey(ip)) found.put(ip, name);
        }
    }

    private static void doScan(final int tcpPort) throws Exception {
        Set<String> bases = new HashSet<String>();
        List<InetAddress> bcasts = new ArrayList<InetAddress>();
        for (NetworkInterface ni : Collections.list(NetworkInterface.getNetworkInterfaces())) {
            if (!ni.isUp() || ni.isLoopback()) continue;
            for (InterfaceAddress ia : ni.getInterfaceAddresses()) {
                InetAddress a = ia.getAddress();
                if (a instanceof Inet4Address && a.isSiteLocalAddress()) {
                    String h = a.getHostAddress();
                    bases.add(h.substring(0, h.lastIndexOf('.') + 1));
                    if (ia.getBroadcast() != null) bcasts.add(ia.getBroadcast());
                }
            }
        }
        DatagramSocket s = new DatagramSocket();
        s.setBroadcast(true);
        s.setSoTimeout(300);
        byte[] q = Q.getBytes("UTF-8");
        for (InetAddress b : bcasts) {
            try {
                s.send(new DatagramPacket(q, q.length, b, UDP));
            } catch (Exception ignored) {
            }
        }
        try {
            s.send(new DatagramPacket(q, q.length, InetAddress.getByName("255.255.255.255"), UDP));
        } catch (Exception ignored) {
        }

        ExecutorService ex = Executors.newFixedThreadPool(48);
        for (String base : bases) {
            for (int i = 1; i < 255; i++) {
                final String ip = base + i;
                ex.execute(new Runnable() {
                    @Override
                    public void run() {
                        Socket k = new Socket();
                        try {
                            k.connect(new InetSocketAddress(ip, tcpPort), 400);
                            add(ip, "");
                        } catch (Exception ignored) {
                        } finally {
                            try {
                                k.close();
                            } catch (Exception ignored) {
                            }
                        }
                    }
                });
            }
        }
        ex.shutdown();

        long start = System.currentTimeMillis();
        long end = start + 5000;
        byte[] buf = new byte[256];
        while (System.currentTimeMillis() < end) {
            try {
                DatagramPacket p = new DatagramPacket(buf, buf.length);
                s.receive(p);
                String r = new String(p.getData(), 0, p.getLength(), "UTF-8");
                String[] pr = r.split("\\|");
                if (pr.length > 0 && pr[0].equals(A)) add(p.getAddress().getHostAddress(), pr.length > 2 ? pr[2] : "?");
            } catch (SocketTimeoutException e) {
                if (ex.isTerminated() && System.currentTimeMillis() - start > 1500) break;
            } catch (Exception ignored) {
            }
        }
        s.close();
    }

    static String result() {
        JSONArray a = new JSONArray();
        synchronized (found) {
            for (Map.Entry<String, String> e : found.entrySet()) a.put(ChatServer.J("ip", e.getKey(), "name", e.getValue()));
        }
        return ChatServer.J("done", !scanning, "list", a).toString();
    }
}

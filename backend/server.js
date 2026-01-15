// ===============================
// Sound Of Praise — Backend V1.2 (Brevo + Reminders + Attendance CSV)
// Render-ready — Node ESM
// ===============================

import "dotenv/config";
import express from "express";
import cors from "cors";
import Stripe from "stripe";
import jwt from "jsonwebtoken";
import crypto from "crypto";

// -------------------------------
// ENV
// -------------------------------
const PORT = process.env.PORT || 4242;
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";
const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:5173";
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || "";

const BREVO_API_KEY = process.env.BREVO_API_KEY || "";
const MAIL_FROM = process.env.MAIL_FROM || "contact@soundofpraise.fr";
const MAIL_FROM_NAME = process.env.MAIL_FROM_NAME || "Sound Of Praise";
const APP_PUBLIC_URL = process.env.APP_PUBLIC_URL || FRONTEND_URL; // netlify url recommended
const CRON_SECRET = process.env.CRON_SECRET || "";

// Logs utiles
console.log("✅ FRONTEND_URL =", FRONTEND_URL);
console.log("✅ APP_PUBLIC_URL =", APP_PUBLIC_URL);
console.log("✅ STRIPE key present =", !!STRIPE_SECRET_KEY);
console.log("✅ BREVO key present =", !!BREVO_API_KEY);
console.log("✅ CRON_SECRET present =", !!CRON_SECRET);

// -------------------------------
// INIT
// -------------------------------
const app = express();
const stripe = STRIPE_SECRET_KEY ? new Stripe(STRIPE_SECRET_KEY) : null;

app.use(
  cors({
    origin: FRONTEND_URL,
    credentials: true,
  })
);
app.use(express.json());

// -------------------------------
// Helpers
// -------------------------------
function uid(prefix = "id") {
  return `${prefix}_${Math.random().toString(16).slice(2)}_${Date.now()}`;
}

function ymd(d) {
  const dt = new Date(d);
  if (Number.isNaN(dt.getTime())) return "";
  return dt.toISOString().slice(0, 10);
}

function daysBetweenUTC(a, b) {
  // diff in days between dates (UTC midnight)
  const da = new Date(`${ymd(a)}T00:00:00.000Z`).getTime();
  const db = new Date(`${ymd(b)}T00:00:00.000Z`).getTime();
  return Math.round((db - da) / (24 * 3600 * 1000));
}

function csvEscape(v) {
  const s = String(v ?? "");
  if (s.includes('"') || s.includes(";") || s.includes("\n") || s.includes("\r")) {
    return `"${s.replaceAll('"', '""')}"`;
  }
  return s;
}

function signUnsubToken(email) {
  // token = HMAC(email)
  return crypto.createHmac("sha256", JWT_SECRET).update(String(email).toLowerCase()).digest("hex");
}

function isUnsubTokenValid(email, token) {
  return signUnsubToken(email) === token;
}

// -------------------------------
// In-memory storage (V1.2)
// NOTE: Sur Render (Free), la mémoire est volatile au redémarrage.
// -------------------------------
let SETTINGS = {
  membershipFeeCents: 2000, // 20€
  reminders: {
    enabled: true,
    // Default schedule: J-2 and J-0
    daysBefore: [2, 0],
    sendHourLocal: 9, // informational
  },
};

let ADMIN_USERS = [{ id: "admin_1", email: "admin@sop.local", role: "admin" }];

let MEMBERS = [
  // { id, name, email, optInEmail, unsubscribed }
];

let EVENTS = [
  // { id, type:"repetition"|"concert", title, date, note, location, remindersEnabled }
];

let MESSAGES = [
  // { id, name, email, subject, message, createdAt }
];

let ATTENDANCE = [
  // { id, eventId, memberEmail, status:"present"|"absent"|"excused", note, createdAt }
];

let REMINDER_LOGS = [
  // { id, eventId, kind:"D2"|"D0", sentAtYmd }
];

// -------------------------------
// AUTH
// -------------------------------
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: "No token" });

  const token = header.replace("Bearer ", "");
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}

function requireAdmin(req, res, next) {
  if (req.user?.role !== "admin") return res.status(403).json({ error: "Forbidden" });
  next();
}

// -------------------------------
// CORE
// -------------------------------
app.get("/api/health", (req, res) => res.json({ ok: true }));

app.get("/api/me", auth, (req, res) => res.json({ user: req.user }));

// -------------------------------
// AUTH — LOGIN TEST (TEMPORAIRE)
// admin si email contient "admin" OU finit par "@sop.local"
// -------------------------------
app.post("/api/auth/login", (req, res) => {
  const { email } = req.body || {};
  if (!email || typeof email !== "string") return res.status(400).json({ error: "Email required" });

  const e = email.toLowerCase().trim();
  const isAdmin = e.includes("admin") || e.endsWith("@sop.local");

  const user = {
    id: isAdmin ? "admin_1" : "user_1",
    email: e,
    role: isAdmin ? "admin" : "member",
  };

  const token = jwt.sign(user, JWT_SECRET, { expiresIn: "7d" });

  // keep admin list in sync (demo)
  if (isAdmin && !ADMIN_USERS.find((u) => u.email === e)) {
    ADMIN_USERS.unshift({ id: uid("u"), email: e, role: "admin" });
  }

  // ensure member record exists for normal members (demo)
  if (!isAdmin) {
    if (!MEMBERS.find((m) => m.email === e)) {
      MEMBERS.unshift({ id: uid("m"), name: "", email: e, optInEmail: false, unsubscribed: false });
    }
  }

  res.json({ token, user });
});

// -------------------------------
// MEMBER — Profile (opt-in email, name)
// -------------------------------
app.get("/api/member/profile", auth, (req, res) => {
  const email = req.user?.email;
  const m = MEMBERS.find((x) => x.email === email);
  res.json({
    profile: m || { id: "self", name: "", email, optInEmail: false, unsubscribed: false },
  });
});

app.patch("/api/member/profile", auth, (req, res) => {
  const email = req.user?.email;
  const { name, optInEmail } = req.body || {};
  let m = MEMBERS.find((x) => x.email === email);

  if (!m) {
    m = { id: uid("m"), name: "", email, optInEmail: false, unsubscribed: false };
    MEMBERS.unshift(m);
  }

  if (name !== undefined) m.name = String(name);
  if (optInEmail !== undefined) m.optInEmail = Boolean(optInEmail);

  // if user re-opt-in, clear unsubscribe flag
  if (m.optInEmail) m.unsubscribed = false;

  res.json({ ok: true, profile: m });
});

// -------------------------------
// ADMIN SETTINGS — Cotisation + Reminders config
// -------------------------------
app.get("/api/admin/settings", auth, requireAdmin, (req, res) => res.json(SETTINGS));

app.patch("/api/admin/settings", auth, requireAdmin, (req, res) => {
  const { membershipFeeCents, reminders } = req.body || {};

  if (membershipFeeCents !== undefined) {
    const n = Number(membershipFeeCents);
    if (!Number.isFinite(n) || n < 0 || n > 1000000) {
      return res.status(400).json({ error: "Invalid membershipFeeCents" });
    }
    SETTINGS.membershipFeeCents = Math.round(n);
  }

  if (reminders !== undefined) {
    SETTINGS.reminders = {
      ...SETTINGS.reminders,
      ...reminders,
    };
  }

  res.json({ ok: true, settings: SETTINGS });
});

// -------------------------------
// ADMIN — USERS (admins/members list for UI)
// -------------------------------
app.get("/api/admin/users", auth, requireAdmin, (req, res) => res.json({ users: ADMIN_USERS }));

app.all("/api/admin/users", auth, requireAdmin, (req, res) => {
  const { email, role } = req.body || {};
  if (!email) return res.status(400).json({ error: "email required" });

  const u = {
    id: uid("u"),
    email: String(email).toLowerCase().trim(),
    role: role === "admin" ? "admin" : "member",
  };
  ADMIN_USERS.unshift(u);
  res.json({ ok: true, user: u });
});

app.delete("/api/admin/users/:id", auth, requireAdmin, (req, res) => {
  const before = ADMIN_USERS.length;
  ADMIN_USERS = ADMIN_USERS.filter((u) => u.id !== req.params.id);
  res.json({ ok: true, removed: before !== ADMIN_USERS.length });
});

// -------------------------------
// ADMIN — MEMBERS (choristes)
// -------------------------------
app.get("/api/admin/members", auth, requireAdmin, (req, res) => res.json({ members: MEMBERS }));

app.post("/api/admin/members", auth, requireAdmin, (req, res) => {
  const { name, email, optInEmail } = req.body || {};
  if (!email) return res.status(400).json({ error: "email required" });

  const e = String(email).toLowerCase().trim();
  if (MEMBERS.find((m) => m.email === e)) {
    return res.status(409).json({ error: "Member already exists" });
  }

  const m = {
    id: uid("m"),
    name: name ? String(name) : "",
    email: e,
    optInEmail: Boolean(optInEmail),
    unsubscribed: false,
  };

  MEMBERS.unshift(m);
  res.json({ ok: true, member: m });
});

app.patch("/api/admin/members/:id", auth, requireAdmin, (req, res) => {
  const idx = MEMBERS.findIndex((m) => m.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: "Member not found" });

  const { name, optInEmail } = req.body || {};
  if (name !== undefined) MEMBERS[idx].name = String(name);
  if (optInEmail !== undefined) MEMBERS[idx].optInEmail = Boolean(optInEmail);

  if (MEMBERS[idx].optInEmail) MEMBERS[idx].unsubscribed = false;

  res.json({ ok: true, member: MEMBERS[idx] });
});

app.delete("/api/admin/members/:id", auth, requireAdmin, (req, res) => {
  const before = MEMBERS.length;
  MEMBERS = MEMBERS.filter((m) => m.id !== req.params.id);
  res.json({ ok: true, removed: before !== MEMBERS.length });
});

// -------------------------------
// ADMIN — EVENTS (répétitions / concerts)
// -------------------------------
app.get("/api/admin/events", auth, requireAdmin, (req, res) => res.json({ events: EVENTS }));

app.post("/api/admin/events", auth, requireAdmin, (req, res) => {
  const { type, title, date, note, location, remindersEnabled } = req.body || {};
  if (!type || !date) return res.status(400).json({ error: "type and date required" });

  const ev = {
    id: uid("e"),
    type: type === "concert" ? "concert" : "repetition",
    title: title || (type === "concert" ? "Concert" : "Répétition"),
    date,
    note: note || "",
    location: location || "",
    remindersEnabled: remindersEnabled !== undefined ? Boolean(remindersEnabled) : true,
  };

  EVENTS.unshift(ev);
  res.json({ ok: true, event: ev });
});

app.patch("/api/admin/events/:id", auth, requireAdmin, (req, res) => {
  const idx = EVENTS.findIndex((e) => e.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: "Event not found" });

  const { type, title, date, note, location, remindersEnabled } = req.body || {};
  EVENTS[idx] = {
    ...EVENTS[idx],
    ...(type !== undefined ? { type: type === "concert" ? "concert" : "repetition" } : {}),
    ...(title !== undefined ? { title } : {}),
    ...(date !== undefined ? { date } : {}),
    ...(note !== undefined ? { note } : {}),
    ...(location !== undefined ? { location } : {}),
    ...(remindersEnabled !== undefined ? { remindersEnabled: Boolean(remindersEnabled) } : {}),
  };

  res.json({ ok: true, event: EVENTS[idx] });
});

app.delete("/api/admin/events/:id", auth, requireAdmin, (req, res) => {
  const before = EVENTS.length;
  EVENTS = EVENTS.filter((e) => e.id !== req.params.id);
  res.json({ ok: true, removed: before !== EVENTS.length });
});

// Public events endpoint (your UI requested /api/events)
app.get("/api/events", (req, res) => res.json({ events: EVENTS }));

// -------------------------------
// MEMBER — Attendance (present/absent/excused)
// -------------------------------
app.get("/api/member/attendance", auth, (req, res) => {
  const email = req.user?.email;
  res.json({ attendance: ATTENDANCE.filter((a) => a.memberEmail === email) });
});

app.post("/api/member/attendance", auth, (req, res) => {
  const email = req.user?.email;
  const { eventId, status, note } = req.body || {};
  if (!eventId || !status) return res.status(400).json({ error: "eventId and status required" });

  const st = String(status);
  if (!["present", "absent", "excused"].includes(st)) {
    return res.status(400).json({ error: "status must be present|absent|excused" });
  }

  // upsert: one record per (eventId, email)
  const existingIdx = ATTENDANCE.findIndex((a) => a.eventId === eventId && a.memberEmail === email);
  const rec = {
    id: existingIdx === -1 ? uid("att") : ATTENDANCE[existingIdx].id,
    eventId,
    memberEmail: email,
    status: st,
    note: note ? String(note) : "",
    createdAt: new Date().toISOString(),
  };

  if (existingIdx === -1) ATTENDANCE.unshift(rec);
  else ATTENDANCE[existingIdx] = rec;

  res.json({ ok: true, attendance: rec });
});

// Admin: list attendance for an event
app.get("/api/admin/events/:id/attendance", auth, requireAdmin, (req, res) => {
  const eventId = req.params.id;
  res.json({ attendance: ATTENDANCE.filter((a) => a.eventId === eventId) });
});

// Admin: export attendance CSV (Excel-friendly)
// GET /api/admin/attendance/export?from=YYYY-MM-DD&to=YYYY-MM-DD
app.get("/api/admin/attendance/export", auth, requireAdmin, (req, res) => {
  const from = req.query.from ? String(req.query.from) : "";
  const to = req.query.to ? String(req.query.to) : "";

  const fromY = from ? new Date(`${from}T00:00:00.000Z`) : null;
  const toY = to ? new Date(`${to}T23:59:59.999Z`) : null;

  const eventById = new Map(EVENTS.map((e) => [e.id, e]));

  const rows = ATTENDANCE
    .map((a) => {
      const ev = eventById.get(a.eventId);
      return { a, ev };
    })
    .filter(({ ev }) => !!ev)
    .filter(({ ev }) => {
      if (!fromY && !toY) return true;
      const d = new Date(ev.date);
      if (fromY && d < fromY) return false;
      if (toY && d > toY) return false;
      return true;
    })
    .sort((x, y) => String(x.ev.date).localeCompare(String(y.ev.date)));

  const header = ["Date", "Type", "Titre", "Lieu", "Choriste", "Statut", "Note", "Horodatage"];
  const lines = [header.map(csvEscape).join(";")];

  for (const { a, ev } of rows) {
    lines.push(
      [ymd(ev.date), ev.type, ev.title, ev.location || "", a.memberEmail, a.status, a.note || "", a.createdAt]
        .map(csvEscape)
        .join(";")
    );
  }

  const csv = lines.join("\n");
  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader(
    "Content-Disposition",
    `attachment; filename="attendance_${from || "all"}_${to || "all"}.csv"`
  );
  res.send(csv);
});

// -------------------------------
// PUBLIC — Content / contact / unsubscribe
// -------------------------------
app.get("/api/public/content", (req, res) => {
  const today = ymd(new Date());
  const upcomingConcerts = EVENTS
    .filter((e) => e.type === "concert")
    .filter((e) => ymd(e.date) >= today)
    .slice(0, 50);

  res.json({
    content: {
      associationName: "Sound Of Praise",
      portfolioPdfUrl: "", // optional
      contactEmail: MAIL_FROM,
      socials: { instagram: "", facebook: "", youtube: "" },
      upcomingConcerts,
    },
  });
});

app.post("/api/public/contact", (req, res) => {
  const { name, email, subject, message } = req.body || {};
  if (!email || !message) return res.status(400).json({ error: "email and message required" });

  const m = {
    id: uid("msg"),
    name: name ? String(name) : "",
    email: String(email).toLowerCase().trim(),
    subject: subject ? String(subject) : "",
    message: String(message),
    createdAt: new Date().toISOString(),
  };

  MESSAGES.unshift(m);
  res.json({ ok: true });
});

// Admin reads messages
app.get("/api/admin/messages", auth, requireAdmin, (req, res) => {
  res.json({ messages: MESSAGES });
});

app.get("/api/public/unsubscribe", (req, res) => {
  const email = req.query.email ? String(req.query.email).toLowerCase().trim() : "";
  const token = req.query.token ? String(req.query.token) : "";

  if (!email || !token || !isUnsubTokenValid(email, token)) {
    return res.status(400).send("Invalid unsubscribe link.");
  }

  let m = MEMBERS.find((x) => x.email === email);
  if (!m) {
    m = { id: uid("m"), name: "", email, optInEmail: false, unsubscribed: true };
    MEMBERS.unshift(m);
  } else {
    m.optInEmail = false;
    m.unsubscribed = true;
  }

  res
    .status(200)
    .send(
      `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Désinscription</title></head><body style="font-family:system-ui;background:#0b0f19;color:#fff;padding:24px;max-width:760px;margin:auto"><h2>Sound Of Praise</h2><p>✅ Adresse <b>${email}</b> désinscrite des rappels.</p><p>Tu peux réactiver depuis l’app (profil) quand tu veux.</p></body></html>`
    );
});

// -------------------------------
// BREVO — Send email
// -------------------------------
async function sendBrevoEmail({ toEmail, toName, subject, html }) {
  if (!BREVO_API_KEY) throw new Error("BREVO_API_KEY missing");
  const payload = {
    sender: { name: MAIL_FROM_NAME, email: MAIL_FROM },
    to: [{ email: toEmail, name: toName || "" }],
    subject,
    htmlContent: html,
  };

  const r = await fetch("https://api.brevo.com/v3/smtp/email", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "api-key": BREVO_API_KEY,
      accept: "application/json",
    },
    body: JSON.stringify(payload),
  });

  if (!r.ok) {
    const txt = await r.text();
    throw new Error(`Brevo error ${r.status}: ${txt}`);
  }
  return r.json();
}

function reminderEmailHtml({ ev, kind, memberEmail }) {
  const dateStr = new Date(ev.date).toLocaleString("fr-FR", { dateStyle: "full", timeStyle: "short" });
  const unsubToken = signUnsubToken(memberEmail);
  const unsubUrl = `${APP_PUBLIC_URL}/api/public/unsubscribe?email=${encodeURIComponent(memberEmail)}&token=${encodeURIComponent(unsubToken)}`;

  const title = ev.type === "concert" ? "Concert" : "Répétition";
  const badge = kind === "D2" ? "Rappel J-2" : "Rappel du jour";

  // Quick action links (optional)
  const base = `${APP_PUBLIC_URL}/#`;
  const presentUrl = `${base}/presence?eventId=${encodeURIComponent(ev.id)}&status=present`;
  const absentUrl = `${base}/presence?eventId=${encodeURIComponent(ev.id)}&status=absent`;
  const excusedUrl = `${base}/presence?eventId=${encodeURIComponent(ev.id)}&status=excused`;

  return `
  <div style="font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial; background:#0b0f19; color:#fff; padding:24px;">
    <div style="max-width:720px; margin:0 auto; border-radius:16px; overflow:hidden; border:1px solid rgba(255,255,255,.08);">
      <div style="padding:18px 20px; background:linear-gradient(135deg, rgba(255,120,120,.25), rgba(161,84,255,.20));">
        <div style="display:flex; align-items:center; justify-content:space-between; gap:12px;">
          <div>
            <div style="font-size:14px; opacity:.9;">Sound Of Praise • ${badge}</div>
            <div style="font-size:22px; font-weight:800; margin-top:6px;">${title} — ${ev.title || ""}</div>
          </div>
          <div style="font-weight:700; color:#D4AF37;">🔥</div>
        </div>
      </div>

      <div style="padding:18px 20px;">
        <p style="margin:0 0 10px 0; font-size:16px;"><b>Date :</b> ${dateStr}</p>
        ${ev.location ? `<p style="margin:0 0 10px 0; font-size:16px;"><b>Lieu :</b> ${ev.location}</p>` : ""}
        ${ev.note ? `<p style="margin:0 0 14px 0; font-size:16px;"><b>Note :</b> ${ev.note}</p>` : ""}

        <div style="display:flex; gap:10px; flex-wrap:wrap; margin:14px 0 18px 0;">
          <a href="${presentUrl}" style="padding:10px 12px; border-radius:10px; background:rgba(0,255,165,.15); color:#fff; text-decoration:none; border:1px solid rgba(0,255,165,.25); font-weight:700;">✅ Présent</a>
          <a href="${absentUrl}" style="padding:10px 12px; border-radius:10px; background:rgba(255,90,90,.12); color:#fff; text-decoration:none; border:1px solid rgba(255,90,90,.25); font-weight:700;">❌ Absent</a>
          <a href="${excusedUrl}" style="padding:10px 12px; border-radius:10px; background:rgba(120,170,255,.12); color:#fff; text-decoration:none; border:1px solid rgba(120,170,255,.25); font-weight:700;">🟦 Excusé</a>
        </div>

        <p style="margin:0; font-size:13px; opacity:.85;">
          Tu reçois ce mail car tu as activé les rappels.
          <a href="${unsubUrl}" style="color:#D4AF37; text-decoration:underline;">Se désinscrire</a>.
        </p>
      </div>
    </div>
  </div>
  `;
}

function reminderKindForDays(d) {
  return d === 2 ? "D2" : d === 0 ? "D0" : null;
}

function hasLog(eventId, kind, sentAtYmd) {
  return REMINDER_LOGS.some((l) => l.eventId === eventId && l.kind === kind && l.sentAtYmd === sentAtYmd);
}

function addLog(eventId, kind, sentAtYmd) {
  REMINDER_LOGS.unshift({ id: uid("rl"), eventId, kind, sentAtYmd });
}

// -------------------------------
// CRON — Run reminders (Brevo)
// POST /api/admin/reminders/run?secret=...
// -------------------------------
app.post("/api/admin/reminders/run", async (req, res) => {
  try {
    const secret = req.query.secret ? String(req.query.secret) : "";
    if (!CRON_SECRET || secret !== CRON_SECRET) {
      return res.status(401).json({ ok: false, error: "Unauthorized" });
    }

    if (!SETTINGS.reminders?.enabled) {
      return res.json({ ok: true, skipped: true, reason: "Reminders disabled" });
    }

    const today = new Date();
    const todayYmd = ymd(today);

    const daysBefore = Array.isArray(SETTINGS.reminders?.daysBefore)
      ? SETTINGS.reminders.daysBefore
      : [2, 0];

    const targets = EVENTS
      .filter((ev) => ev.remindersEnabled !== false)
      .map((ev) => ({ ev, d: daysBetweenUTC(today, ev.date) })) // eventDate - today
      .filter(({ d }) => daysBefore.includes(d))
      .map(({ ev, d }) => ({ ev, kind: reminderKindForDays(d) }))
      .filter((x) => !!x.kind);

    const recipients = MEMBERS.filter((m) => m.optInEmail && !m.unsubscribed && m.email);

    let sent = 0;
    const details = [];

    for (const { ev, kind } of targets) {
      if (hasLog(ev.id, kind, todayYmd)) {
        details.push({ eventId: ev.id, kind, skipped: true, reason: "Already sent today" });
        continue;
      }

      for (const m of recipients) {
        const subject = `${kind === "D2" ? "Rappel" : "Aujourd'hui"} : ${ev.type === "concert" ? "Concert" : "Répétition"} — ${ymd(ev.date)} — Sound Of Praise`;
        const html = reminderEmailHtml({ ev, kind, memberEmail: m.email });

        await sendBrevoEmail({
          toEmail: m.email,
          toName: m.name || "",
          subject,
          html,
        });

        sent += 1;
      }

      addLog(ev.id, kind, todayYmd);
      details.push({ eventId: ev.id, kind, sentTo: recipients.length });
    }

    return res.json({ ok: true, today: todayYmd, eventsMatched: targets.length, recipients: recipients.length, sent, details });
  } catch (err) {
    console.error("❌ reminders/run error:", err);
    return res.status(500).json({ ok: false, error: err.message || "Error" });
  }
});

// Admin can manually trigger a test reminder for an eventId to one email
app.post("/api/admin/reminders/test", auth, requireAdmin, async (req, res) => {
  try {
    const { eventId, toEmail } = req.body || {};
    if (!eventId || !toEmail) return res.status(400).json({ error: "eventId and toEmail required" });

    const ev = EVENTS.find((e) => e.id === eventId);
    if (!ev) return res.status(404).json({ error: "Event not found" });

    const html = reminderEmailHtml({ ev, kind: "D2", memberEmail: String(toEmail).toLowerCase().trim() });
    await sendBrevoEmail({
      toEmail: String(toEmail).toLowerCase().trim(),
      toName: "",
      subject: `TEST Rappel — ${ev.title || ev.type} — Sound Of Praise`,
      html,
    });

    res.json({ ok: true });
  } catch (err) {
    console.error("❌ reminders/test error:", err);
    res.status(500).json({ error: err.message || "Error" });
  }
});

// -------------------------------
// Stripe — Cotisation (dynamic amount)
// -------------------------------
app.post("/api/member/checkout", auth, async (req, res) => {
  try {
    if (!stripe) {
      return res.status(500).json({ error: "Stripe not configured (missing STRIPE_SECRET_KEY)" });
    }

    const amountCents = Number(SETTINGS?.membershipFeeCents ?? 2000);
    if (!Number.isFinite(amountCents) || amountCents <= 0) {
      return res.status(400).json({ error: "Invalid membership fee amount" });
    }

    const session = await stripe.checkout.sessions.create({
      mode: "payment",
      payment_method_types: ["card"],
      line_items: [
        {
          quantity: 1,
          price_data: {
            currency: "eur",
            unit_amount: Math.round(amountCents),
            product_data: {
              name: "Cotisation Sound Of Praise",
              description: "Cotisation mensuelle (paiement manuel)",
            },
          },
        },
      ],
      success_url: `${FRONTEND_URL}/#/paiement/success`,
      cancel_url: `${FRONTEND_URL}/#/paiement/cancel`,
      metadata: {
        userId: req.user?.id || "unknown",
        email: req.user?.email || "unknown",
        role: req.user?.role || "unknown",
      },
    });

    return res.json({ url: session.url });
  } catch (err) {
    console.error("❌ Stripe checkout error:", err);
    return res.status(500).json({ error: err.message || "Stripe error" });
  }
});

// -------------------------------
// ADMIN — Stats (optional)
// -------------------------------
app.get("/api/admin/stats", auth, requireAdmin, (req, res) => {
  res.json({
    stats: {
      totalAdmins: ADMIN_USERS.filter((u) => u.role === "admin").length,
      totalMembers: MEMBERS.length,
      totalEvents: EVENTS.length,
      totalMessages: MESSAGES.length,
      attendanceRows: ATTENDANCE.length,
    },
  });
});

// -------------------------------
// Anti-404 fallback (safe stubs)
// -------------------------------
app.all("/api/admin/*", auth, requireAdmin, (req, res) => {
  res.status(200).json({ ok: false, error: "Not implemented yet", path: req.path });
});

app.all("/api/public/*", (req, res) => {
  res.status(200).json({ ok: false, error: "Not implemented yet", path: req.path });
});

app.all("/api/member/*", auth, (req, res) => {
  res.status(200).json({ ok: false, error: "Not implemented yet", path: req.path });
});

// -------------------------------
// START
// -------------------------------
app.listen(PORT, () => {
  console.log(`🚀 Backend V1.2 running on port ${PORT}`);
});

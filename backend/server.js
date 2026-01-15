// =======================================
// Sound Of Praise — Backend V1.2 FINAL
// Brevo + Cron (GET) + Présences + Export CSV
// =======================================

import "dotenv/config";
import express from "express";
import cors from "cors";
import Stripe from "stripe";
import jwt from "jsonwebtoken";
import crypto from "crypto";

// ---------------------------------------
// ENV
// ---------------------------------------
const PORT = process.env.PORT || 4242;
const FRONTEND_URL = process.env.FRONTEND_URL;
const APP_PUBLIC_URL = process.env.APP_PUBLIC_URL || FRONTEND_URL;
const JWT_SECRET = process.env.JWT_SECRET;
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;
const BREVO_API_KEY = process.env.BREVO_API_KEY;
const MAIL_FROM = process.env.MAIL_FROM;
const MAIL_FROM_NAME = process.env.MAIL_FROM_NAME || "Sound Of Praise";
const CRON_SECRET = process.env.CRON_SECRET;

// ---------------------------------------
// INIT
// ---------------------------------------
const app = express();
const stripe = STRIPE_SECRET_KEY ? new Stripe(STRIPE_SECRET_KEY) : null;

app.use(cors({ origin: FRONTEND_URL, credentials: true }));
app.use(express.json());

// ---------------------------------------
// HELPERS
// ---------------------------------------
const uid = (p = "id") =>
  `${p}_${Math.random().toString(16).slice(2)}_${Date.now()}`;

const ymd = (d) => new Date(d).toISOString().slice(0, 10);

const signUnsubToken = (email) =>
  crypto.createHmac("sha256", JWT_SECRET).update(email).digest("hex");

const csvEscape = (v) => {
  const s = String(v ?? "");
  return s.includes(";") || s.includes('"')
    ? `"${s.replaceAll('"', '""')}"`
    : s;
};

// ---------------------------------------
// IN-MEMORY DATA (V1.2)
// ---------------------------------------
let SETTINGS = {
  membershipFeeCents: 2000,
  reminders: { enabled: true, daysBefore: [2, 0] },
};

let ADMIN_USERS = [{ id: "admin_1", email: "admin@sop.local", role: "admin" }];
let MEMBERS = []; // {id,name,email,optInEmail,unsubscribed}
let EVENTS = []; // {id,type,title,date,note,location,remindersEnabled}
let ATTENDANCE = []; // {id,eventId,memberEmail,status,note,createdAt}
let MESSAGES = [];
let REMINDER_LOGS = [];

// ---------------------------------------
// AUTH
// ---------------------------------------
function auth(req, res, next) {
  const h = req.headers.authorization;
  if (!h) return res.status(401).json({ error: "No token" });
  try {
    req.user = jwt.verify(h.replace("Bearer ", ""), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
}

const requireAdmin = (req, res, next) =>
  req.user?.role === "admin"
    ? next()
    : res.status(403).json({ error: "Forbidden" });

// ---------------------------------------
// CORE
// ---------------------------------------
app.get("/api/health", (_, res) => res.json({ ok: true }));
app.get("/api/me", auth, (req, res) => res.json({ user: req.user }));

// ---------------------------------------
// LOGIN (TEMPORAIRE)
// ---------------------------------------
app.post("/api/auth/login", (req, res) => {
  const email = req.body?.email?.toLowerCase();
  if (!email) return res.status(400).json({ error: "Email required" });

  const isAdmin = email.includes("admin") || email.endsWith("@sop.local");
  const user = { id: uid("u"), email, role: isAdmin ? "admin" : "member" };
  const token = jwt.sign(user, JWT_SECRET, { expiresIn: "7d" });

  if (isAdmin && !ADMIN_USERS.find((u) => u.email === email))
    ADMIN_USERS.push({ id: uid("a"), email, role: "admin" });

  if (!isAdmin && !MEMBERS.find((m) => m.email === email))
    MEMBERS.push({ id: uid("m"), name: "", email, optInEmail: false });

  res.json({ token, user });
});

// ---------------------------------------
// MEMBER PROFILE
// ---------------------------------------
app.get("/api/member/profile", auth, (req, res) => {
  const m = MEMBERS.find((x) => x.email === req.user.email);
  res.json({ profile: m || {} });
});

app.patch("/api/member/profile", auth, (req, res) => {
  let m = MEMBERS.find((x) => x.email === req.user.email);
  if (!m) {
    m = { id: uid("m"), email: req.user.email };
    MEMBERS.push(m);
  }
  if (req.body.name !== undefined) m.name = req.body.name;
  if (req.body.optInEmail !== undefined)
    m.optInEmail = Boolean(req.body.optInEmail);
  res.json({ ok: true, profile: m });
});

// ---------------------------------------
// ADMIN SETTINGS
// ---------------------------------------
app.get("/api/admin/settings", auth, requireAdmin, (_, res) =>
  res.json(SETTINGS)
);

app.patch("/api/admin/settings", auth, requireAdmin, (req, res) => {
  if (req.body.membershipFeeCents !== undefined)
    SETTINGS.membershipFeeCents = Number(req.body.membershipFeeCents);
  if (req.body.reminders)
    SETTINGS.reminders = { ...SETTINGS.reminders, ...req.body.reminders };
  res.json({ ok: true });
});

// ---------------------------------------
// EVENTS
// ---------------------------------------
app.get("/api/events", (_, res) => res.json({ events: EVENTS }));
app.get("/api/admin/events", auth, requireAdmin, (_, res) =>
  res.json({ events: EVENTS })
);

app.post("/api/admin/events", auth, requireAdmin, (req, res) => {
  const ev = {
    id: uid("e"),
    remindersEnabled: true,
    ...req.body,
  };
  EVENTS.push(ev);
  res.json({ ok: true, event: ev });
});

app.delete("/api/admin/events/:id", auth, requireAdmin, (req, res) => {
  EVENTS = EVENTS.filter((e) => e.id !== req.params.id);
  res.json({ ok: true });
});

// ---------------------------------------
// ATTENDANCE
// ---------------------------------------
app.post("/api/member/attendance", auth, (req, res) => {
  ATTENDANCE = ATTENDANCE.filter(
    (a) =>
      !(
        a.eventId === req.body.eventId &&
        a.memberEmail === req.user.email
      )
  );
  ATTENDANCE.push({
    id: uid("att"),
    eventId: req.body.eventId,
    memberEmail: req.user.email,
    status: req.body.status,
    note: req.body.note || "",
    createdAt: new Date().toISOString(),
  });
  res.json({ ok: true });
});

app.get("/api/admin/attendance/export", auth, requireAdmin, (_, res) => {
  const header = [
    "Date",
    "Event",
    "Email",
    "Status",
    "Note",
    "Timestamp",
  ];
  const lines = [header.join(";")];
  ATTENDANCE.forEach((a) =>
    lines.push(
      [
        ymd(new Date()),
        a.eventId,
        a.memberEmail,
        a.status,
        a.note,
        a.createdAt,
      ]
        .map(csvEscape)
        .join(";")
    )
  );
  res
    .setHeader("Content-Type", "text/csv")
    .setHeader("Content-Disposition", "attachment; filename=attendance.csv")
    .send(lines.join("\n"));
});

// ---------------------------------------
// BREVO EMAIL
// ---------------------------------------
async function sendBrevo(to, subject, html) {
  await fetch("https://api.brevo.com/v3/smtp/email", {
    method: "POST",
    headers: {
      "api-key": BREVO_API_KEY,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      sender: { email: MAIL_FROM, name: MAIL_FROM_NAME },
      to: [{ email: to }],
      subject,
      htmlContent: html,
    }),
  });
}

// ---------------------------------------
// CRON — GET OK (cron-job.org)
// ---------------------------------------
app.all("/api/admin/reminders/run", async (req, res) => {
  if (req.query.secret !== CRON_SECRET)
    return res.status(401).json({ error: "Unauthorized" });

  const today = ymd(new Date());
  let sent = 0;

  for (const ev of EVENTS) {
    if (!ev.remindersEnabled) continue;
    const diff = Math.round(
      (new Date(ev.date) - new Date()) / 86400000
    );
    if (![0, 2].includes(diff)) continue;
    if (REMINDER_LOGS.find((l) => l.eventId === ev.id && l.day === today))
      continue;

    for (const m of MEMBERS.filter((x) => x.optInEmail)) {
      await sendBrevo(
        m.email,
        `Rappel ${ev.title}`,
        `<p>${ev.title} le ${ev.date}</p>`
      );
      sent++;
    }
    REMINDER_LOGS.push({ eventId: ev.id, day: today });
  }

  res.json({ ok: true, sent });
});

// ---------------------------------------
// STRIPE
// ---------------------------------------
app.post("/api/member/checkout", auth, async (_, res) => {
  const session = await stripe.checkout.sessions.create({
    mode: "payment",
    line_items: [
      {
        quantity: 1,
        price_data: {
          currency: "eur",
          unit_amount: SETTINGS.membershipFeeCents,
          product_data: { name: "Cotisation Sound Of Praise" },
        },
      },
    ],
    success_url: `${FRONTEND_URL}/#/paiement/success`,
    cancel_url: `${FRONTEND_URL}/#/paiement/cancel`,
  });
  res.json({ url: session.url });
});

// ---------------------------------------
// START
// ---------------------------------------
app.listen(PORT, () =>
  console.log(`🔥 Sound Of Praise backend V1.2 running`)
);

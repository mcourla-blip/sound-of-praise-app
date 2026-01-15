// ===============================
// Sound Of Praise — Backend V1.1.2 (anti-404 stubs)
// Render-ready — Node ESM
// ===============================

import "dotenv/config";
import express from "express";
import cors from "cors";
import Stripe from "stripe";
import jwt from "jsonwebtoken";

// -------------------------------
// ENV
// -------------------------------
const PORT = process.env.PORT || 4242;
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";
const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:5173";
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;

console.log("✅ FRONTEND_URL =", FRONTEND_URL);
console.log("✅ STRIPE_SECRET_KEY present =", !!STRIPE_SECRET_KEY);

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

// -------------------------------
// In-memory storage (V1.1.x)
// -------------------------------
let SETTINGS = { membershipFeeCents: 2000 }; // 20€ par défaut

let ADMIN_USERS = [{ id: "admin_1", email: "admin@sop.local", role: "admin" }];
let ADMIN_MEMBERS = []; // { id, name, email }
let ADMIN_EVENTS = []; // { id, type: "repetition"|"concert", title, date, note }
let ADMIN_MESSAGES = []; // { id, name, email, subject, message, createdAt }

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
// Core
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

  // sync admin list (démo)
  if (isAdmin && !ADMIN_USERS.find((u) => u.email === e)) {
    ADMIN_USERS.unshift({ id: uid("u"), email: e, role: "admin" });
  }

  res.json({ token, user });
});

// -------------------------------
// ADMIN SETTINGS — COTISATION
// -------------------------------
app.get("/api/admin/settings", auth, requireAdmin, (req, res) => res.json(SETTINGS));

app.patch("/api/admin/settings", auth, requireAdmin, (req, res) => {
  const { membershipFeeCents } = req.body || {};
  if (membershipFeeCents === undefined) {
    return res.status(400).json({ error: "membershipFeeCents is required" });
  }
  const n = Number(membershipFeeCents);
  if (!Number.isFinite(n) || n < 0 || n > 1000000) {
    return res.status(400).json({ error: "Invalid membershipFeeCents" });
  }
  SETTINGS.membershipFeeCents = Math.round(n);
  res.json({ ok: true, settings: SETTINGS });
});

// -------------------------------
// ADMIN — USERS
// -------------------------------
app.get("/api/admin/users", auth, requireAdmin, (req, res) => res.json({ users: ADMIN_USERS }));

app.post("/api/admin/users", auth, requireAdmin, (req, res) => {
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

app.patch("/api/admin/users/:id", auth, requireAdmin, (req, res) => {
  const idx = ADMIN_USERS.findIndex((u) => u.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: "User not found" });

  const { email, role } = req.body || {};
  ADMIN_USERS[idx] = {
    ...ADMIN_USERS[idx],
    ...(email !== undefined ? { email: String(email).toLowerCase().trim() } : {}),
    ...(role !== undefined ? { role: role === "admin" ? "admin" : "member" } : {}),
  };
  res.json({ ok: true, user: ADMIN_USERS[idx] });
});

app.delete("/api/admin/users/:id", auth, requireAdmin, (req, res) => {
  const before = ADMIN_USERS.length;
  ADMIN_USERS = ADMIN_USERS.filter((u) => u.id !== req.params.id);
  res.json({ ok: true, removed: before !== ADMIN_USERS.length });
});

// -------------------------------
// ADMIN — MEMBERS
// -------------------------------
app.get("/api/admin/members", auth, requireAdmin, (req, res) => res.json({ members: ADMIN_MEMBERS }));

app.post("/api/admin/members", auth, requireAdmin, (req, res) => {
  const { name, email } = req.body || {};
  if (!name) return res.status(400).json({ error: "name required" });

  const m = { id: uid("m"), name: String(name), email: email ? String(email) : "" };
  ADMIN_MEMBERS.unshift(m);
  res.json({ ok: true, member: m });
});

app.delete("/api/admin/members/:id", auth, requireAdmin, (req, res) => {
  const before = ADMIN_MEMBERS.length;
  ADMIN_MEMBERS = ADMIN_MEMBERS.filter((m) => m.id !== req.params.id);
  res.json({ ok: true, removed: before !== ADMIN_MEMBERS.length });
});

// -------------------------------
// ADMIN — EVENTS
// -------------------------------
app.get("/api/admin/events", auth, requireAdmin, (req, res) => res.json({ events: ADMIN_EVENTS }));

app.post("/api/admin/events", auth, requireAdmin, (req, res) => {
  const { type, title, date, note } = req.body || {};
  if (!type || !date) return res.status(400).json({ error: "type and date required" });

  const ev = {
    id: uid("e"),
    type: type === "concert" ? "concert" : "repetition",
    title: title || (type === "concert" ? "Concert" : "Répétition"),
    date,
    note: note || "",
  };
  ADMIN_EVENTS.unshift(ev);
  res.json({ ok: true, event: ev });
});

app.patch("/api/admin/events/:id", auth, requireAdmin, (req, res) => {
  const idx = ADMIN_EVENTS.findIndex((e) => e.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: "Event not found" });

  const { title, date, note, type } = req.body || {};
  ADMIN_EVENTS[idx] = {
    ...ADMIN_EVENTS[idx],
    ...(title !== undefined ? { title } : {}),
    ...(date !== undefined ? { date } : {}),
    ...(note !== undefined ? { note } : {}),
    ...(type !== undefined ? { type: type === "concert" ? "concert" : "repetition" } : {}),
  };
  res.json({ ok: true, event: ADMIN_EVENTS[idx] });
});

app.delete("/api/admin/events/:id", auth, requireAdmin, (req, res) => {
  const before = ADMIN_EVENTS.length;
  ADMIN_EVENTS = ADMIN_EVENTS.filter((e) => e.id !== req.params.id);
  res.json({ ok: true, removed: before !== ADMIN_EVENTS.length });
});

// -------------------------------
// ADMIN — MESSAGES
// -------------------------------
app.get("/api/admin/messages", auth, requireAdmin, (req, res) => {
  res.json({ messages: ADMIN_MESSAGES });
});

// -------------------------------
// ADMIN — STATS + placeholders
// -------------------------------
app.get("/api/admin/stats", auth, requireAdmin, (req, res) => {
  res.json({
    stats: {
      usersCount: ADMIN_USERS.length,
      membersCount: ADMIN_MEMBERS.length,
      eventsCount: ADMIN_EVENTS.length,
      repeatsCount: ADMIN_EVENTS.filter((e) => e.type === "repetition").length,
      concertsCount: ADMIN_EVENTS.filter((e) => e.type === "concert").length,
    },
  });
});

app.get("/api/admin/choristes", auth, requireAdmin, (req, res) => {
  res.json({ choristes: [] });
});

// -------------------------------
// PUBLIC — CONTENT (ce que ton frontend appelle)
// -------------------------------
app.get("/api/public/content", (req, res) => {
  const now = new Date().toISOString().slice(0, 10);

  const upcomingConcerts = ADMIN_EVENTS
    .filter((e) => e.type === "concert")
    .filter((e) => String(e.date).slice(0, 10) >= now)
    .slice(0, 20);

  res.json({
    content: {
      associationName: "Sound Of Praise",
      portfolioPdfUrl: "", // mets une URL si tu en as une (Drive/Dropbox/etc.)
      contactEmail: "soundofpraise@example.com", // change quand tu veux
      socials: {
        instagram: "",
        facebook: "",
        youtube: "",
      },
      upcomingConcerts,
    },
  });
});

// PUBLIC — concerts (utile si l’UI le demande)
app.get("/api/public/concerts", (req, res) => {
  res.json({ concerts: ADMIN_EVENTS.filter((e) => e.type === "concert") });
});

// PUBLIC — contact (form invité)
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
  ADMIN_MESSAGES.unshift(m);
  res.json({ ok: true });
});

// -------------------------------
// MEMBER — STRIPE CHECKOUT
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

    res.json({ url: session.url });
  } catch (err) {
    console.error("❌ Stripe checkout error:", err);
    res.status(500).json({ error: err.message || "Stripe error" });
  }
});

// -------------------------------
// Anti-404 : fallback “safe” pour endpoints futurs
// (évite que ton UI affiche des 404 pendant qu’on ajoute les features)
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
  console.log(`🚀 Backend running on port ${PORT}`);
});

// ===============================
// Sound Of Praise — Backend V1.1 (Render-ready)
// Node 18+ / 20+ / 24+ (ESM)
// ===============================

import "dotenv/config";
import express from "express";
import cors from "cors";
import Stripe from "stripe";
import jwt from "jsonwebtoken";

// -------------------------------
// CONFIG
// -------------------------------
const PORT = process.env.PORT || 4242; // Render fournit souvent PORT
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";
const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:5173";
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;

// Logs utiles
console.log("✅ FRONTEND_URL =", FRONTEND_URL);
console.log("✅ STRIPE_SECRET_KEY present =", !!STRIPE_SECRET_KEY);

// -------------------------------
// INIT
// -------------------------------
const app = express();
const stripe = STRIPE_SECRET_KEY ? new Stripe(STRIPE_SECRET_KEY) : null;

// CORS
app.use(
  cors({
    origin: FRONTEND_URL,
    credentials: true,
  })
);

app.use(express.json());

// -------------------------------
// SETTINGS V1.1 (en mémoire)
// -------------------------------
let SETTINGS = { membershipFeeCents: 2000 }; // 20€ par défaut

// -------------------------------
// AUTH MIDDLEWARE
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
// HEALTH
// -------------------------------
app.get("/api/health", (req, res) => {
  res.json({ ok: true });
});

// -------------------------------
// ME — infos utilisateur connecté
// -------------------------------
app.get("/api/me", auth, (req, res) => {
  res.json({ user: req.user });
});
 
// -------------------------------
// AUTH — LOGIN TEST (TEMPORAIRE)
// admin si email contient "admin" OU finit par "@sop.local"
// ex: admin@sop.local
// -------------------------------
app.post("/api/auth/login", (req, res) => {
  const { email } = req.body || {};

  if (!email || typeof email !== "string") {
    return res.status(400).json({ error: "Email required" });
  }

  const e = email.toLowerCase().trim();
  const isAdmin = e.includes("admin") || e.endsWith("@sop.local");

  const user = {
    id: isAdmin ? "admin_1" : "user_1",
    email: e,
    role: isAdmin ? "admin" : "member",
  };

  const token = jwt.sign(user, JWT_SECRET, { expiresIn: "7d" });
  res.json({ token, user });
});

// -------------------------------
// ADMIN SETTINGS — COTISATION
// -------------------------------
app.get("/api/admin/settings", auth, requireAdmin, (req, res) => {
  res.json(SETTINGS);
});

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
// STRIPE CHECKOUT — COTISATION (montant dynamique)
// POST /api/member/checkout
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
// START
// -------------------------------
app.listen(PORT, () => {
  console.log(`🚀 Backend running on port ${PORT}`);
});

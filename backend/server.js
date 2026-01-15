// ===============================
// Sound Of Praise — Backend stable
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
const PORT = 4242;
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";
const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:5173";
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;

// -------------------------------
// CHECK ENV (clair et net)
// -------------------------------
console.log("✅ FRONTEND_URL =", FRONTEND_URL);
console.log("✅ STRIPE_SECRET_KEY present =", !!STRIPE_SECRET_KEY);

if (!STRIPE_SECRET_KEY) {
  console.error("❌ STRIPE_SECRET_KEY manquant dans backend/.env");
}

// -------------------------------
// INIT
// -------------------------------
const app = express();
const stripe = STRIPE_SECRET_KEY ? new Stripe(STRIPE_SECRET_KEY) : null;

app.use(cors({
  origin: FRONTEND_URL,
  credentials: true
}));
app.use(express.json());

// -------------------------------
// AUTH MIDDLEWARE (simple)
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

// -------------------------------
// TEST ROUTE
// -------------------------------
app.get("/api/health", (req, res) => {
  res.json({ ok: true });
});

// -------------------------------
// STRIPE CHECKOUT — COTISATION
// -------------------------------
app.post("/api/member/checkout", auth, async (req, res) => {
  try {
    if (!stripe) {
      return res.status(500).json({ error: "Stripe not configured" });
    }

    const session = await stripe.checkout.sessions.create({
      mode: "payment",
      payment_method_types: ["card"],
      line_items: [
        {
          quantity: 1,
          price_data: {
            currency: "eur",
            unit_amount: 2000, // 20 €
            product_data: {
              name: "Cotisation Sound Of Praise (mensuelle)"
            }
          }
        }
      ],
      success_url: `${FRONTEND_URL}/#/paiement/success`,
      cancel_url: `${FRONTEND_URL}/#/paiement/cancel`,
      metadata: {
        userId: req.user.id || "unknown",
        email: req.user.email || "unknown"
      }
    });

    res.json({ url: session.url });

  } catch (err) {
    console.error("❌ Stripe checkout error:", err);
    res.status(500).json({ error: err.message });
  }
});

// -------------------------------
// LOGIN DE TEST (TEMPORAIRE)
// -------------------------------
app.post("/api/auth/login", (req, res) => {
  const { email } = req.body;

  // utilisateur fictif pour test
  const user = {
    id: "user_1",
    email,
    role: "member"
  };

  const token = jwt.sign(user, JWT_SECRET, { expiresIn: "7d" });
  res.json({ token, user });
});

// -------------------------------
// START SERVER
// -------------------------------
app.listen(PORT, () => {
  console.log(`🚀 Backend running on http://192.168.0.38:${PORT}`);
});

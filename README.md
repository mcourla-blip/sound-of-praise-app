# Sound Of Praise — Premier jet (PWA installable + API)

Palette UI (comme demandé):
- Or (CTA): #D4AF37
- Nuit: #0B132B
- Turquoise: #2EC4B6
- Fond clair: #F6F7F8

## Prérequis
- Node.js 18+

## 1) Lancer le backend (API)
```bash
cd backend
npm install
cp .env.example .env
npm run dev
```
Un admin est créé au 1er démarrage:
- email: admin@sop.local
- mdp: Admin123!

## 2) Lancer le frontend (PWA)
```bash
cd ../frontend
npm install
npm run dev
```

Ouvre: http://localhost:5173

## Paiement (Stripe)
Le bouton "Payer la cotisation" ouvre Stripe Checkout.
Pour voir les paiements se confirmer en base, il faut configurer le webhook Stripe (voir backend/.env.example).

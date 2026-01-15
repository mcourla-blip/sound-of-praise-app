const API = "http://192.168.0.38:4242/api";

export function setToken(t){ localStorage.setItem("sop_token", t || ""); }
export function getToken(){ return localStorage.getItem("sop_token") || ""; }
export function logout(){ setToken(""); }

async function request(path, { method="GET", body, auth=false } = {}){
  const headers = { "Content-Type":"application/json" };
  if(auth){
    const t = getToken();
    if(t) headers.Authorization = `Bearer ${t}`;
  }
  const res = await fetch(`${API}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined
  });
  const data = await res.json().catch(()=> ({}));
  if(!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

export const api = {
    // V1.1 — Settings + Checkout
  adminGetSettings: () => request(`/admin/settings`, { method: "GET", auth: true }),
  adminUpdateSettings: (payload) => request(`/admin/settings`, { method: "PATCH", auth: true, body: payload }),

  createCheckoutSession: () => request(`/member/checkout`, { method: "POST", auth: true }),

  login: (email, password) => request("/auth/login", { method:"POST", body:{ email, password }}),
  me: () => request("/me", { auth:true }),

  publicContent: () => request("/public/content"),
  publicConcerts: () => request("/public/concerts"),
  publicContact: (payload) => request("/public/contact", { method:"POST", body: payload }),

  events: () => request("/events", { auth:true }),
  myAttendance: () => request("/attendance/my", { auth:true }),
  setAttendance: (payload) => request("/attendance", { method:"POST", auth:true, body: payload }),

  checkout: () => request("/payments/checkout", { method:"POST", auth:true }),
  myPayments: () => request("/payments/my", { auth:true }),

  // Admin — événements (modifier / supprimer)
  adminUpdateEvent: (id, payload) => request(`/admin/events/${id}`, { method:"PATCH", auth:true, body: payload }),
  adminDeleteEvent: (id) => request(`/admin/events/${id}`, { method:"DELETE", auth:true }),
  adminUsers: () => request("/admin/users", { auth:true }),
  adminCreateUser: (payload) => request("/admin/users", { method:"POST", auth:true, body: payload }),
  adminCreateEvent: (payload) => request("/admin/events", { method:"POST", auth:true, body: payload }),
  adminStats: () => request("/admin/stats", { auth:true }),
  adminMessages: () => request("/admin/messages", { auth:true }),
  adminPublicContent: (payload) => request("/admin/public-content", { method:"POST", auth:true, body: payload }),
};

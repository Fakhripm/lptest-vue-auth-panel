import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "node:crypto";

const app = express();
const PORT = Number(process.env.PORT || 4000);
const SECRET = process.env.JWT_SECRET || "dev-secret-change-me";
const users = new Map(); // email -> { id, email, passwordHash, name }

app.use(cors());
app.use(express.json());

function issueTokens(user, { remember = false } = {}) {
  const expiresIn = remember ? "30d" : "1d";
  const token = jwt.sign({ sub: user.id, email: user.email, typ: "access" }, SECRET, {
    expiresIn
  });
  const refreshToken = jwt.sign(
    { sub: user.id, email: user.email, typ: "refresh" },
    SECRET,
    { expiresIn: "60d" }
  );
  return { token, refreshToken, expiresIn };
}

function publicUser(user) {
  return { id: user.id, email: user.email, name: user.name };
}

app.get("/health", (_req, res) => res.json({ ok: true }));

app.post("/auth/register", async (req, res) => {
  const { email, password, name, remember } = req.body || {};
  if (!email || !password || password.length < 6) {
    return res.status(400).json({ ok: false, error: "email + password(min 6) required" });
  }
  if (users.has(email)) return res.status(409).json({ ok: false, error: "email taken" });
  const passwordHash = await bcrypt.hash(password, 10);
  const user = {
    id: crypto.randomUUID(),
    email,
    name: name || email.split("@")[0],
    passwordHash
  };
  users.set(email, user);
  const tokens = issueTokens(user, { remember: !!remember });
  res.status(201).json({ ok: true, ...tokens, user: publicUser(user) });
});

app.post("/auth/login", async (req, res) => {
  const { email, password, remember } = req.body || {};
  const user = users.get(email);
  if (!user || !(await bcrypt.compare(password || "", user.passwordHash))) {
    return res.status(401).json({ ok: false, error: "invalid credentials" });
  }
  const tokens = issueTokens(user, { remember: !!remember });
  res.json({ ok: true, ...tokens, user: publicUser(user) });
});

/**
 * Stateless logout: clients discard access + refresh tokens.
 * No server-side denylist in this demo.
 */
app.post("/auth/logout", (_req, res) => {
  res.json({
    ok: true,
    message: "Stateless logout — discard access and refresh tokens on the client."
  });
});

app.post("/auth/refresh", (req, res) => {
  const refreshToken = req.body?.refreshToken;
  if (!refreshToken) {
    return res.status(400).json({ ok: false, error: "refreshToken required" });
  }
  try {
    const payload = jwt.verify(refreshToken, SECRET);
    if (payload.typ !== "refresh") {
      return res.status(401).json({ ok: false, error: "invalid refresh token" });
    }
    const user = [...users.values()].find((u) => u.id === payload.sub);
    if (!user) return res.status(401).json({ ok: false, error: "unauthorized" });
    const tokens = issueTokens(user, { remember: false });
    res.json({ ok: true, ...tokens, user: publicUser(user) });
  } catch {
    res.status(401).json({ ok: false, error: "unauthorized" });
  }
});

app.get("/auth/me", (req, res) => {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ ok: false, error: "unauthorized" });
  try {
    const payload = jwt.verify(token, SECRET);
    if (payload.typ && payload.typ !== "access") {
      return res.status(401).json({ ok: false, error: "unauthorized" });
    }
    const user = [...users.values()].find((u) => u.id === payload.sub);
    if (!user) return res.status(401).json({ ok: false, error: "unauthorized" });
    res.json({
      ok: true,
      user: publicUser(user),
      iat: payload.iat,
      exp: payload.exp
    });
  } catch {
    res.status(401).json({ ok: false, error: "unauthorized" });
  }
});

app.listen(PORT, () => console.log(`vue-auth-panel API on :${PORT}`));

import React, { useEffect, useMemo, useState } from "react";
import {
  fetchAuditLogs,
  fetchFindings,
  fetchMe,
  login,
  register,
} from "./api";
import StitchPage from "./StitchPage";

const initialLoginForm = {
  email: "",
  password: "",
};

const initialRegisterForm = {
  username: "",
  email: "",
  password: "",
};

const navItems = [
  { key: "dashboard", label: "Dashboard" },
  { key: "findings", label: "Findings" },
  { key: "triage", label: "Triage" },
  { key: "audit", label: "Audit Logs" },
  { key: "settings", label: "Settings" },
];

export default function App() {
  const [findings, setFindings] = useState([]);
  const [token, setToken] = useState(() => localStorage.getItem("sb_token") || "");
  const [currentUser, setCurrentUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [loginForm, setLoginForm] = useState(initialLoginForm);
  const [registerForm, setRegisterForm] = useState(initialRegisterForm);
  const [authMode, setAuthMode] = useState("login");
  const [activeNav, setActiveNav] = useState("dashboard");
  const [auditLogs, setAuditLogs] = useState([]);

  useEffect(() => {
    if (window.location.pathname !== "/") {
      window.history.replaceState({}, "", "/");
    }
  }, []);

  async function loadFindings(authToken) {
    try {
      const data = await fetchFindings(authToken);
      setFindings(data.items || []);
    } catch (err) {
      setError(parseError(err));
    }
  }

  async function loadAudit(authToken) {
    try {
      const data = await fetchAuditLogs(authToken);
      setAuditLogs(data.items || []);
    } catch (err) {
      if (!String(err?.message || "").includes("forbidden")) {
        setError(parseError(err));
      }
    }
  }

  useEffect(() => {
    async function bootstrap() {
      if (!token) {
        setLoading(false);
        return;
      }

      try {
        const profile = await fetchMe(token);
        setCurrentUser(profile);
        await Promise.all([loadFindings(token), loadAudit(token)]);
      } catch (err) {
        localStorage.removeItem("sb_token");
        setToken("");
        setCurrentUser(null);
        setError(parseError(err));
      } finally {
        setLoading(false);
      }
    }

    bootstrap();
  }, [token]);

  async function handleLogin(event) {
    event.preventDefault();
    setError("");

    try {
      const data = await login(loginForm);
      localStorage.setItem("sb_token", data.token);
      setToken(data.token);
      setCurrentUser(data.user);
      setLoginForm(initialLoginForm);
    } catch (err) {
      setError(parseError(err));
    }
  }

  async function handleRegister(event) {
    event.preventDefault();
    setError("");

    try {
      const data = await register(registerForm);
      localStorage.setItem("sb_token", data.token);
      setToken(data.token);
      setCurrentUser(data.user);
      setRegisterForm(initialRegisterForm);
    } catch (err) {
      setError(parseError(err));
    }
  }

  function handleLogout() {
    localStorage.removeItem("sb_token");
    setToken("");
    setCurrentUser(null);
    setFindings([]);
    setAuditLogs([]);
    setActiveNav("dashboard");
    setError("");
  }

  const aiTopFinding = findings.find((item) => item.ai_priority === "critical") || findings[0];

  const stitchData = useMemo(
    () => ({
      findingStats: {
        open: findings.filter((item) => item.status === "open").length,
        critical: findings.filter((item) => item.severity === "critical").length,
        triaged: findings.filter((item) => item.status === "triaged").length,
        auditEvents: auditLogs.length,
      },
      aiSummary: aiTopFinding
        ? {
            title: aiTopFinding.title,
            description: aiTopFinding.ai_summary || aiTopFinding.description || "",
            confidence: aiTopFinding.ai_confidence || 0,
          }
        : null,
      findings,
      auditLogs,
    }),
    [findings, auditLogs, aiTopFinding]
  );

  if (!currentUser) {
    return (
      <main className="auth-shell">
        <section className="hero-panel">
          <p className="hero-kicker">Secure Bounty Board</p>
          <h1>The Sovereign Ledger</h1>
          <p>
            A clean enterprise SaaS workspace for vulnerability management, AI triage,
            and audit-grade traceability.
          </p>
        </section>

        <section className="auth-panel">
          <h2>{authMode === "login" ? "Access Portal" : "Create Secure Account"}</h2>
          {error ? <p className="error">{error}</p> : null}
          <div className="auth-switch" role="tablist" aria-label="Authentication Mode">
            <button
              type="button"
              className={`switch-btn ${authMode === "login" ? "active" : ""}`}
              onClick={() => setAuthMode("login")}
            >
              Login
            </button>
            <button
              type="button"
              className={`switch-btn ${authMode === "register" ? "active" : ""}`}
              onClick={() => setAuthMode("register")}
            >
              Register
            </button>
          </div>

          {authMode === "login" ? (
            <form onSubmit={handleLogin} className="form-grid cardless auth-form-single">
              <h3>Login</h3>
              <input
                type="email"
                placeholder="Email"
                value={loginForm.email}
                onChange={(e) => setLoginForm({ ...loginForm, email: e.target.value })}
                required
              />
              <input
                type="password"
                placeholder="Password"
                value={loginForm.password}
                onChange={(e) => setLoginForm({ ...loginForm, password: e.target.value })}
                required
              />
              <button type="submit" disabled={loading}>Initialize Session</button>
              <p className="muted auth-helper">
                Belum punya akun?{" "}
                <button type="button" className="link-btn" onClick={() => setAuthMode("register")}>Buat akun</button>
              </p>
            </form>
          ) : (
            <form onSubmit={handleRegister} className="form-grid cardless auth-form-single">
              <h3>Register</h3>
              <input
                placeholder="Username"
                value={registerForm.username}
                onChange={(e) => setRegisterForm({ ...registerForm, username: e.target.value })}
                required
              />
              <input
                type="email"
                placeholder="Email"
                value={registerForm.email}
                onChange={(e) => setRegisterForm({ ...registerForm, email: e.target.value })}
                required
              />
              <input
                type="password"
                placeholder="Password (min 8 chars)"
                value={registerForm.password}
                onChange={(e) => setRegisterForm({ ...registerForm, password: e.target.value })}
                required
              />
              <button type="submit" disabled={loading}>Create Account</button>
              <p className="muted auth-helper">
                Sudah punya akun?{" "}
                <button type="button" className="link-btn" onClick={() => setAuthMode("login")}>Login</button>
              </p>
            </form>
          )}
        </section>
      </main>
    );
  }

  return (
    <>
      <div className="app-toolbar">
        <div className="toolbar-nav">
          {navItems.map((item) => (
            <button
              key={item.key}
              type="button"
              className={`toolbar-btn ${activeNav === item.key ? "active" : ""}`}
              onClick={() => setActiveNav(item.key)}
            >
              {item.label}
            </button>
          ))}
        </div>
        <button type="button" className="logout-btn" onClick={handleLogout}>
          Logout ({currentUser.username})
        </button>
      </div>

      <StitchPage pageName={activeNav} data={stitchData} />

      {error ? (
        <div className="error-banner">
          <strong>Error:</strong> {error}
        </div>
      ) : null}
    </>
  );
}

function parseError(err) {
  const message = String(err?.message || "Request failed");
  if (message.startsWith("{")) {
    try {
      const parsed = JSON.parse(message);
      return parsed.error || message;
    } catch {
      return message;
    }
  }
  return message;
}

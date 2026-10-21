import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { ShieldCheck, Mail, Lock, ArrowRight, RefreshCw, X } from "lucide-react";
import { request, setCsrfToken, apiBaseUrl } from "../api/client";

interface OperatorUser {
  id: string;
  email: string;
}

interface Session {
  user: OperatorUser;
  csrf_token: string;
  expires_at?: string;
}

interface AuthContextType {
  session: Session | null;
  loading: boolean;
  isModalOpen: boolean;
  openModal: (mode?: "login" | "register") => void;
  closeModal: () => void;
  logout: () => Promise<void>;
  requireAuth: (callback: () => void) => void;
}

const AuthContext = createContext<AuthContextType>({
  session: null,
  loading: true,
  isModalOpen: false,
  openModal: () => {},
  closeModal: () => {},
  logout: async () => {},
  requireAuth: () => {},
});

export function OperatorSessionProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<Session | null>(null);
  const [loading, setLoading] = useState(true);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [authMode, setAuthMode] = useState<"login" | "register">("login");
  const [email, setEmail] = useState(() => {
    try {
      return localStorage.getItem("kavach_operator_email") || "";
    } catch {
      return "";
    }
  });
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [postAuthCallback, setPostAuthCallback] = useState<(() => void) | null>(null);
  const hadPriorSession = useRef(false);

  useEffect(() => {
    let active = true;
    request<Session>("/api/auth/me")
      .then(value => {
        if (active) {
          setCsrfToken(value.csrf_token);
          setSession(value);
          hadPriorSession.current = true;
          if (value.user?.email) {
            setEmail(value.user.email);
            try {
              localStorage.setItem("kavach_operator_email", value.user.email);
            } catch {
              // Ignore localStorage issues
            }
          }
        }
      })
      .catch(() => {})
      .finally(() => {
        if (active) setLoading(false);
      });

    const expired = () => {
      setCsrfToken("");
      setSession(null);
      setAuthMode("login"); // Always default to Login mode on expiration
      if (hadPriorSession.current) {
        setError("Your session expired. Please sign in again.");
      } else {
        setError("");
      }
      setIsModalOpen(true);
    };

    const handleLogout = () => {
      request("/api/auth/logout", { method: "POST" })
        .finally(() => {
          setCsrfToken("");
          setSession(null);
          hadPriorSession.current = false;
        });
    };

    window.addEventListener("sentinel-session-expired", expired);
    window.addEventListener("sentinel-disconnect", handleLogout);
    return () => {
      active = false;
      window.removeEventListener("sentinel-session-expired", expired);
      window.removeEventListener("sentinel-disconnect", handleLogout);
    };
  }, []);

  const openModal = (mode: "login" | "register" = "login") => {
    setAuthMode(mode);
    setError("");
    setIsModalOpen(true);
  };

  const closeModal = () => {
    setIsModalOpen(false);
    setError("");
    setPostAuthCallback(null);
  };

  const logout = async () => {
    try {
      await request("/api/auth/logout", { method: "POST" });
    } finally {
      setCsrfToken("");
      setSession(null);
      hadPriorSession.current = false;
    }
  };

  const requireAuth = (callback: () => void) => {
    if (session) {
      callback();
    } else {
      setPostAuthCallback(() => callback);
      openModal("login");
    }
  };

  async function submit() {
    if (busy) return;
    setBusy(true);
    setError("");
    try {
      const endpoint = authMode === "register" ? "/api/auth/register" : "/api/auth/login";
      const value = await request<Session>(endpoint, {
        method: "POST",
        body: JSON.stringify({ email: email.trim().toLowerCase(), password }),
      });
      setCsrfToken(value.csrf_token);
      setSession(value);
      hadPriorSession.current = true;
      try {
        localStorage.setItem("kavach_operator_email", email.trim().toLowerCase());
      } catch {
        // Ignore localStorage error
      }
      setPassword("");
      setIsModalOpen(false);
      if (postAuthCallback) {
        postAuthCallback();
        setPostAuthCallback(null);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "Authentication failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthContext.Provider
      value={{
        session,
        loading,
        isModalOpen,
        openModal,
        closeModal,
        logout,
        requireAuth,
      }}
    >
      {children}

      {/* Auth Modal / Gate */}
      {isModalOpen && (
        <div className="auth-modal-overlay" onClick={closeModal} role="dialog" aria-modal="true">
          <div className="auth-modal-container" onClick={e => e.stopPropagation()}>
            <button className="auth-modal-close" onClick={closeModal} aria-label="Close modal">
              <X size={18} />
            </button>

            <div className="auth-header">
              <div className="auth-badge">
                <span className="auth-badge-dot"></span>
                <span>OPERATOR ACCESS</span>
              </div>
              <h2 className="auth-title">
                {authMode === "register" ? "Create Operator Identity" : "Operator Sign In"}
              </h2>
              <p className="auth-subtitle">
                {authMode === "register"
                  ? "Register a local cryptographic operator credential to run scans, approve patches, and export evidence."
                  : "Sign in with your operator credentials to access Mission Control, review patches, and verify code."}
              </p>
            </div>

            <form
              className="auth-form"
              onSubmit={event => {
                event.preventDefault();
                void submit();
              }}
            >
              <div className="auth-field">
                <label htmlFor="auth-email">Operator Email</label>
                <div className="auth-input-wrapper">
                  <Mail size={16} className="auth-input-icon" />
                  <input
                    id="auth-email"
                    type="email"
                    placeholder="operator@kavach-x.local"
                    value={email}
                    onChange={e => setEmail(e.target.value)}
                    autoComplete="email"
                    required
                  />
                </div>
              </div>

              <div className="auth-field">
                <label htmlFor="auth-password">Passphrase (min 12 chars)</label>
                <div className="auth-input-wrapper">
                  <Lock size={16} className="auth-input-icon" />
                  <input
                    id="auth-password"
                    type="password"
                    placeholder="••••••••••••••••"
                    value={password}
                    onChange={e => setPassword(e.target.value)}
                    autoComplete={authMode === "register" ? "new-password" : "current-password"}
                    minLength={12}
                    required
                  />
                </div>
              </div>

              {error && (
                <div className="auth-error-banner" role="alert">
                  {error}
                </div>
              )}

              <button type="submit" className="button button-lime auth-submit-btn" disabled={busy}>
                {busy ? (
                  <>
                    <RefreshCw size={16} className="spin" />
                    <span>Validating credentials…</span>
                  </>
                ) : (
                  <>
                    <ShieldCheck size={16} />
                    <span>{authMode === "register" ? "Establish Identity" : "Sign In"}</span>
                    <ArrowRight size={16} />
                  </>
                )}
              </button>
            </form>

            <div className="auth-footer">
              <button
                type="button"
                className="auth-toggle-link"
                onClick={() => {
                  setAuthMode(m => (m === "login" ? "register" : "login"));
                  setError("");
                }}
              >
                {authMode === "register"
                  ? "Already have an operator account? Sign In"
                  : "Need a new operator identity? Register"}
              </button>

              <div className="auth-docs-link">
                <a href={`${apiBaseUrl}/docs`} target="_blank" rel="noreferrer">
                  Open Backend OpenAPI Documentation ↗
                </a>
              </div>
            </div>
          </div>
        </div>
      )}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
export default OperatorSessionProvider;

import { useState } from "react";
import { useNavigate } from "react-router-dom";
import api, { setCookie } from "../api/api";
import Header from "../Header/Header";
import "./Login.css";

function Login() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const navigate = useNavigate();

  const login = async (e) => {
    e.preventDefault();
    setError("");

    if (!email || !password) {
      setError("Please fill in all fields");
      return;
    }

    setLoading(true);
    try {
      const response = await api.post("/login", {
        email,
        password,
      });
      console.log("[Login] Response:", response.data);

      // Extract tokens from response.data.data
      const accessToken = response.data.data?.access_token;
      const refreshToken = response.data.data?.refresh_token;

      if (accessToken) {
        setCookie("token", accessToken, 7);
        console.log("[Login] ✅ Access token stored");
      }

      if (refreshToken) {
        setCookie("refresh_token", refreshToken, 30);
        console.log("[Login] ✅ Refresh token stored");
      }

      navigate("/dashboard");
    } catch (err) {
      console.log("[Login] ❌ Error:", err.response?.data);
      setError(
        err.response?.data?.message || "Login failed. Please try again.",
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-page">
      <Header />
      {/* <header className="page-header">
        <div className="header-content">
          <div className="logo">
            <img src="https://via.placeholder.com/150x40?text=Guardlynx" alt="Guardlynx Logo" className="logo-img" />
          </div>
          <div className="header-info">
            <h2>Guardlynx</h2>
            <p>Security Management System</p>
          </div>
          <nav className="header-nav">
            <a href="/register" className="nav-link">Sign Up</a>
          </nav>
        </div>
      </header> */}

      <div className="login-container">
        <div className="card">
          <div className="card-header">
            <h1>Welcome Back</h1>
            <p>Sign in to your account</p>
          </div>

          <form onSubmit={login}>
            {error && <div className="error-message">{error}</div>}

            <div className="input-group">
              <label htmlFor="email">Email</label>
              <input
                id="email"
                type="email"
                placeholder="Enter your email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                disabled={loading}
              />
            </div>

            <div className="input-group">
              <label htmlFor="password">Password</label>
              <input
                id="password"
                type="password"
                placeholder="Enter your password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                disabled={loading}
              />
            </div>

            {/* <a href="/forgot-password" className="forgot-password">Forgot password?</a> */}

            <button
              type="submit"
              className={`login-btn ${loading ? "loading" : ""}`}
              disabled={loading}
            >
              {loading ? "Signing in..." : "Sign In"}
            </button>
          </form>

          <div className="signup-link">
            Don't have an account? <a href="/register">Sign up here</a>
          </div>
        </div>
      </div>
    </div>
  );
}

export default Login;

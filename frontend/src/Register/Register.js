import { useState } from "react";
import { useNavigate } from "react-router-dom";
import api from "../api/api";
import "./Register.css";
import Header from "../Header/Header";

function Register() {
  const [form, setForm] = useState({
    first_name: "",
    last_name: "",
    email: "",
    mobile: "",
    password: "",
    confirmPassword: "",
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const navigate = useNavigate();

  const handleChange = (e) => {
    const { name, value } = e.target;
    setForm({ ...form, [name]: value });
  };

  const validateForm = () => {
    if (
      !form.first_name ||
      !form.last_name ||
      !form.email ||
      !form.mobile ||
      !form.password ||
      !form.confirmPassword
    ) {
      setError("Please fill in all fields");
      return false;
    }

    if (!/^\S+@\S+\.\S+$/.test(form.email)) {
      setError("Please enter a valid email address");
      return false;
    }

    if (!/^\d{10}$/.test(form.mobile.replace(/\D/g, ""))) {
      setError("Please enter a valid 10-digit phone number");
      return false;
    }

    if (form.password.length < 6) {
      setError("Password must be at least 6 characters long");
      return false;
    }

    if (form.password !== form.confirmPassword) {
      setError("Passwords do not match");
      return false;
    }

    return true;
  };

  const register = async (e) => {
    e.preventDefault();
    setError("");
    setSuccess("");

    if (!validateForm()) {
      return;
    }

    setLoading(true);
    try {
      const response = await api.post("/signup", {
        first_name: form.first_name,
        last_name: form.last_name,
        email: form.email,
        phone_number: form.mobile,
        password: form.password,
        country_code: "+91",
      });

      setSuccess("Account created successfully! Redirecting to login...");
      setForm({
        first_name: "",
        last_name: "",
        email: "",
        mobile: "",
        password: "",
        confirmPassword: "",
      });

      setTimeout(() => {
        navigate("/login");
      }, 2000);
    } catch (err) {
      setError(
        err.response?.data?.message || "Registration failed. Please try again.",
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="register-page">
      <Header />
      <div className="register-container">
        <div className="card">
          <div className="card-header">
            <h1>Create Account</h1>
            <p>Join us today</p>
          </div>

          <form onSubmit={register}>
            {error && <div className="error-message">{error}</div>}
            {success && <div className="success-message">{success}</div>}

            <div className="input-group">
              <label htmlFor="firstname">First Name</label>
              <input
                id="firstname"
                type="text"
                name="first_name"
                placeholder="Enter your first name"
                value={form.first_name}
                onChange={handleChange}
                disabled={loading}
              />
            </div>

            <div className="input-group">
              <label htmlFor="last_name">Last Name</label>
              <input
                id="lastname"
                type="text"
                name="last_name"
                placeholder="Enter your last name"
                value={form.last_name}
                onChange={handleChange}
                disabled={loading}
              />
            </div>

            <div className="input-group">
              <label htmlFor="email">Email</label>
              <input
                id="email"
                type="email"
                name="email"
                placeholder="Enter your email"
                value={form.email}
                onChange={handleChange}
                disabled={loading}
              />
            </div>

            <div className="input-group">
              <label htmlFor="mobile">Phone Number</label>
              <input
                id="mobile"
                type="tel"
                name="mobile"
                placeholder="Enter your phone number"
                value={form.mobile}
                onChange={handleChange}
                disabled={loading}
              />
            </div>

            <div className="input-group">
              <label htmlFor="password">Password</label>
              <input
                id="password"
                type="password"
                name="password"
                placeholder="Create a password"
                value={form.password}
                onChange={handleChange}
                disabled={loading}
              />
            </div>

            <div className="input-group">
              <label htmlFor="confirmPassword">Confirm Password</label>
              <input
                id="confirmPassword"
                type="password"
                name="confirmPassword"
                placeholder="Confirm your password"
                value={form.confirmPassword}
                onChange={handleChange}
                disabled={loading}
              />
            </div>

            <button
              type="submit"
              className={`register-btn ${loading ? "loading" : ""}`}
              disabled={loading}
            >
              {loading ? "Creating Account..." : "Sign Up"}
            </button>
          </form>

          <div className="login-link">
            Already have an account? <a href="/login">Sign in here</a>
          </div>
        </div>
      </div>
    </div>
  );
}

export default Register;

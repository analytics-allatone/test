import { BrowserRouter, Routes, Route } from "react-router-dom";
import logo from "./logo.svg";
import "./App.css";
import Header from "./DashboardHeader/dashboard-Header";
import Login from "./Login/Login";
import Register from "./Register/Register";
import Dashboard from "./Dashboard/Dashboard";
import ForgotPage from "./ForgotPage/forgot-page";
import InstallationProcess from "./InstallationProcess/InstallationProcess";

function App() {
  return (
    <div className="App">
      <BrowserRouter>
        <Routes>
          {/* when home page template is created then this route will be used instead of the login route */}
          <Route path="/" element={<Login />} />
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />
          <Route path="/forgot-password" element={<ForgotPage />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/installation" element={<InstallationProcess />} />
        </Routes>
      </BrowserRouter>
    </div>
  );
}

export default App;

import { BrowserRouter, Link, Route, Routes } from "react-router-dom";
import AdminDashboard from "./pages/AdminDashboard";
import AdminLogin from "./pages/AdminLogin";
import AdminManagement from "./pages/AdminManagement";
import AdminRegister from "./pages/AdminRegister";
import MySubmissions from "./pages/MySubmissions";
import SubmitAadhaar from "./pages/SubmitAadhaar";
import UserLogin from "./pages/UserLogin";
import UserSignup from "./pages/UserSignup";
import "./App.css";

export default function App() {
  return (
    <BrowserRouter>
      <nav className="top-nav">
        <Link to="/">Submit</Link>
        <Link to="/login">Log In</Link>
        <Link to="/signup">Sign Up</Link>
        <Link to="/admin/login">Admin</Link>
      </nav>
      <Routes>
        <Route path="/" element={<SubmitAadhaar />} />
        <Route path="/login" element={<UserLogin />} />
        <Route path="/signup" element={<UserSignup />} />
        <Route path="/my-submissions" element={<MySubmissions />} />
        <Route path="/admin/login" element={<AdminLogin />} />
        <Route path="/admin/register" element={<AdminRegister />} />
        <Route path="/admin" element={<AdminDashboard />} />
        <Route path="/admin/manage" element={<AdminManagement />} />
      </Routes>
    </BrowserRouter>
  );
}

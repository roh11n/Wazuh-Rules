import { BrowserRouter, Routes, Route } from "react-router-dom";
import { Toaster } from "sonner";
import "@/App.css";
import Topbar from "@/components/Topbar";
import Landing from "@/pages/Landing";
import History from "@/pages/History";
import Detail from "@/pages/Detail";
import Settings from "@/pages/Settings";

function App() {
  return (
    <div className="App dark min-h-screen bg-background text-foreground">
      <BrowserRouter>
        <Topbar />
        <Routes>
          <Route path="/" element={<Landing />} />
          <Route path="/scans" element={<History />} />
          <Route path="/scans/:id" element={<Detail />} />
          <Route path="/settings" element={<Settings />} />
        </Routes>
        <Toaster theme="dark" position="top-right" toastOptions={{ className: "font-mono text-xs" }} />
      </BrowserRouter>
    </div>
  );
}

export default App;

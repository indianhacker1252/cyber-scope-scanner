import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { useEffect, useState } from "react";
import { supabase } from "@/integrations/supabase/client";
import Index from "./pages/Index";
import Login from "./pages/Login";
import NotFound from "./pages/NotFound";

const queryClient = new QueryClient();

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const [loading, setLoading] = useState(true);
  const [authenticated, setAuthenticated] = useState(false);

  useEffect(() => {
    let resolved = false;

    // Timeout fallback — if getSession hangs (stale token, network failure), force redirect to login
    const timeout = setTimeout(() => {
      if (!resolved) {
        resolved = true;
        setAuthenticated(false);
        setLoading(false);
      }
    }, 5000);

    supabase.auth.getSession().then(({ data: { session } }) => {
      if (!resolved) {
        resolved = true;
        clearTimeout(timeout);
        setAuthenticated(!!session);
        setLoading(false);
      }
    }).catch(() => {
      if (!resolved) {
        resolved = true;
        clearTimeout(timeout);
        setAuthenticated(false);
        setLoading(false);
      }
    });

    const { data: { subscription } } = supabase.auth.onAuthStateChange((_event, session) => {
      setAuthenticated(!!session);
      if (!resolved) {
        resolved = true;
        clearTimeout(timeout);
        setLoading(false);
      }
    });

    return () => {
      clearTimeout(timeout);
      subscription.unsubscribe();
    };
  }, []);

  if (loading) return <div className="min-h-screen flex items-center justify-center bg-background text-foreground">Loading...</div>;
  if (!authenticated) return <Navigate to="/login" replace />;
  return <>{children}</>;
}

const App = () => (
  <QueryClientProvider client={queryClient}>
    <TooltipProvider>
      <Toaster />
      <Sonner />
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/" element={<ProtectedRoute><Index /></ProtectedRoute>} />
          {/* ADD ALL CUSTOM ROUTES ABOVE THE CATCH-ALL "*" ROUTE */}
          <Route path="*" element={<NotFound />} />
        </Routes>
      </BrowserRouter>
    </TooltipProvider>
  </QueryClientProvider>
);

export default App;

import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { supabase } from '@/integrations/supabase/client';
import { User } from '@supabase/supabase-js';

export const useAuth = () => {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [userRole, setUserRole] = useState<string | null>(null);
  const navigate = useNavigate();

  useEffect(() => {
    // Check current session
    supabase.auth.getSession().then(({ data: { session } }) => {
      setUser(session?.user ?? null);
      if (session?.user) {
        // Get user role from localStorage or database
        const storedRole = localStorage.getItem('userRole');
        if (storedRole) {
          setUserRole(storedRole);
        } else {
          // Fetch from database
          supabase
            .from('user_roles')
            .select('role')
            .eq('user_id', session.user.id)
            .single()
            .then(({ data }) => {
              const role = data?.role || 'user';
              setUserRole(role);
              localStorage.setItem('userRole', role);
            });
        }
      }
      setLoading(false);
    });

    // Listen for auth changes
    const { data: { subscription } } = supabase.auth.onAuthStateChange((_event, session) => {
      setUser(session?.user ?? null);
      
      if (!session?.user) {
        setUserRole(null);
        localStorage.removeItem('userRole');
        navigate('/login');
      } else {
        // Get user role
        const storedRole = localStorage.getItem('userRole');
        if (storedRole) {
          setUserRole(storedRole);
        } else {
          supabase
            .from('user_roles')
            .select('role')
            .eq('user_id', session.user.id)
            .single()
            .then(({ data }) => {
              const role = data?.role || 'user';
              setUserRole(role);
              localStorage.setItem('userRole', role);
            });
        }
      }
    });

    return () => subscription.unsubscribe();
  }, [navigate]);

  const signOut = async () => {
    await supabase.auth.signOut();
    localStorage.removeItem('userRole');
    navigate('/login');
  };

  return { user, loading, userRole, signOut };
};
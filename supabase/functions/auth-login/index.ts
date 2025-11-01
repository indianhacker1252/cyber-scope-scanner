import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const cors Headers = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const { username, password } = await req.json();
    
    const supabaseUrl = Deno.env.get('SUPABASE_URL')!;
    const supabaseKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
    const supabase = createClient(supabaseUrl, supabaseKey);

    // Check lockout status
    const fifteenMinutesAgo = new Date(Date.now() - 15 * 60 * 1000).toISOString();
    
    const { data: recentAttempts, error: attemptsError } = await supabase
      .from('login_attempts')
      .select('*')
      .eq('username', username)
      .eq('success', false)
      .gte('attempted_at', fifteenMinutesAgo)
      .order('attempted_at', { ascending: false });

    if (attemptsError) {
      console.error('Error checking attempts:', attemptsError);
      return new Response(JSON.stringify({ error: 'Login check failed' }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    // Check if user is locked out (5 failed attempts in last 15 minutes)
    if (recentAttempts && recentAttempts.length >= 5) {
      await supabase.from('login_attempts').insert({
        username,
        success: false,
        ip_address: req.headers.get('x-forwarded-for') || 'unknown'
      });

      return new Response(JSON.stringify({ 
        error: 'Account locked due to too many failed attempts. Try again in 15 minutes.',
        locked: true,
        attemptsRemaining: 0
      }), {
        status: 403,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    // Try to find user by username
    const { data: profile, error: profileError } = await supabase
      .from('profiles')
      .select('id')
      .eq('username', username)
      .maybeSingle();

    if (profileError || !profile) {
      // Record failed attempt
      await supabase.from('login_attempts').insert({
        username,
        success: false,
        ip_address: req.headers.get('x-forwarded-for') || 'unknown'
      });

      const attemptsRemaining = Math.max(0, 5 - (recentAttempts?.length || 0) - 1);
      
      return new Response(JSON.stringify({ 
        error: 'Invalid username or password',
        attemptsRemaining
      }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    // Get user email from auth.users
    const { data: authUser, error: authUserError } = await supabase.auth.admin.getUserById(profile.id);
    
    if (authUserError || !authUser) {
      await supabase.from('login_attempts').insert({
        username,
        success: false,
        ip_address: req.headers.get('x-forwarded-for') || 'unknown'
      });

      const attemptsRemaining = Math.max(0, 5 - (recentAttempts?.length || 0) - 1);
      
      return new Response(JSON.stringify({ 
        error: 'Invalid username or password',
        attemptsRemaining
      }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    // Attempt sign in with email and password
    const { data: signInData, error: signInError } = await supabase.auth.signInWithPassword({
      email: authUser.user.email!,
      password: password,
    });

    if (signInError || !signInData.session) {
      // Record failed attempt
      await supabase.from('login_attempts').insert({
        username,
        success: false,
        ip_address: req.headers.get('x-forwarded-for') || 'unknown'
      });

      const attemptsRemaining = Math.max(0, 5 - (recentAttempts?.length || 0) - 1);
      
      return new Response(JSON.stringify({ 
        error: 'Invalid username or password',
        attemptsRemaining
      }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    // Record successful attempt
    await supabase.from('login_attempts').insert({
      username,
      success: true,
      ip_address: req.headers.get('x-forwarded-for') || 'unknown'
    });

    // Get user role
    const { data: userRole } = await supabase
      .from('user_roles')
      .select('role')
      .eq('user_id', profile.id)
      .single();

    return new Response(JSON.stringify({ 
      session: signInData.session,
      user: signInData.user,
      role: userRole?.role || 'user'
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });

  } catch (error) {
    console.error('Login error:', error);
    return new Response(JSON.stringify({ error: 'Internal server error' }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }
});
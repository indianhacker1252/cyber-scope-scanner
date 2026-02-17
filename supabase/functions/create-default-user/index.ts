import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const supabaseUrl = Deno.env.get('SUPABASE_URL')!;
    const supabaseServiceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
    const supabase = createClient(supabaseUrl, supabaseServiceKey);

    // Require admin authentication - only existing admins can create default users
    const authHeader = req.headers.get('Authorization');
    if (authHeader?.startsWith('Bearer ')) {
      const supabaseAuth = createClient(supabaseUrl, Deno.env.get('SUPABASE_ANON_KEY')!, {
        global: { headers: { Authorization: authHeader } }
      });
      const { data: userData, error: userError } = await supabaseAuth.auth.getUser();
      
      if (!userError && userData?.user) {
        // Verify caller is admin
        const { data: roleData } = await supabase
          .from('user_roles')
          .select('role')
          .eq('user_id', userData.user.id)
          .eq('role', 'admin')
          .maybeSingle();

        if (!roleData) {
          return new Response(JSON.stringify({ error: 'Admin access required' }), {
            status: 403,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          });
        }
      } else {
        return new Response(JSON.stringify({ error: 'Invalid token' }), {
          status: 401,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }
    } else {
      // Allow unauthenticated access ONLY if the kali default user doesn't exist (initial setup)
      const { data: kaliProfile } = await supabase
        .from('profiles')
        .select('id')
        .eq('username', 'kali')
        .maybeSingle();

      if (kaliProfile) {
        // Verify the auth user actually exists
        const { data: authCheck } = await supabase.auth.admin.getUserById(kaliProfile.id);
        if (authCheck?.user) {
          return new Response(JSON.stringify({ error: 'Authentication required. Default user already exists.' }), {
            status: 401,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          });
        }
      }
    }

    // Check if default user already exists
    const { data: existingProfile } = await supabase
      .from('profiles')
      .select('id')
      .eq('username', 'kali')
      .maybeSingle();

    if (existingProfile) {
      // Verify the auth user actually exists
      const { data: authCheck, error: authCheckError } = await supabase.auth.admin.getUserById(existingProfile.id);
      
      if (!authCheckError && authCheck?.user) {
        return new Response(JSON.stringify({ 
          message: 'Default user already exists',
          exists: true 
        }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }
      
      // Auth user is missing (orphaned profile) - clean up and recreate
      console.log('Orphaned profile found, cleaning up...');
      await supabase.from('user_roles').delete().eq('user_id', existingProfile.id);
      await supabase.from('profiles').delete().eq('id', existingProfile.id);
    }

    // Create default user
    const { data: authData, error: authError } = await supabase.auth.admin.createUser({
      email: 'kali@vapt.local',
      password: 'kali',
      email_confirm: true,
      user_metadata: {
        username: 'kali',
        display_name: 'Kali Admin'
      }
    });

    if (authError) {
      console.error('Error creating user:', authError);
      return new Response(JSON.stringify({ error: 'Failed to create default user' }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    // Add admin role
    await supabase
      .from('user_roles')
      .insert({
        user_id: authData.user.id,
        role: 'admin'
      });

    return new Response(JSON.stringify({ 
      message: 'Default user created successfully',
      username: 'kali',
      role: 'admin'
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });

  } catch (error) {
    console.error('Error:', error);
    return new Response(JSON.stringify({ error: 'Internal server error' }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }
});

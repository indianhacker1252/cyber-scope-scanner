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
    const supabaseKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
    const supabase = createClient(supabaseUrl, supabaseKey);

    // Check if default user already exists
    const { data: existingProfile } = await supabase
      .from('profiles')
      .select('id')
      .eq('username', 'kali')
      .maybeSingle();

    if (existingProfile) {
      return new Response(JSON.stringify({ 
        message: 'Default user already exists',
        exists: true 
      }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    // Create default user with username 'kali' and password 'kali'
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
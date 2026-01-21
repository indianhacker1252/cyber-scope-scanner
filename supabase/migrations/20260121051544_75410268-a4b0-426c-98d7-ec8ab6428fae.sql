-- Fix RLS policies for security improvements

-- 1. Drop the overly permissive "Anyone can insert login attempts" policy
-- The auth-login edge function uses service role key which bypasses RLS
DROP POLICY IF EXISTS "Anyone can insert login attempts" ON public.login_attempts;

-- 2. Drop the overly permissive service role policies on ai_learnings and ai_decisions
-- These provide no protection if service role key is compromised
DROP POLICY IF EXISTS "Service role can manage all learnings" ON public.ai_learnings;
DROP POLICY IF EXISTS "Service role can manage all decisions" ON public.ai_decisions;

-- 3. Fix profiles visibility - restrict to own profile only (plus admins)
DROP POLICY IF EXISTS "Users can view all profiles" ON public.profiles;

CREATE POLICY "Users can view own profile"
ON public.profiles FOR SELECT
USING (auth.uid() = id);

CREATE POLICY "Admins can view all profiles"
ON public.profiles FOR SELECT
USING (has_role(auth.uid(), 'admin'::app_role));

-- Fix: Deny anonymous access to profiles table
CREATE POLICY "Deny anonymous access to profiles"
ON public.profiles FOR SELECT
TO anon
USING (false);

-- Fix: Deny anonymous access to login_attempts table
CREATE POLICY "Deny anonymous access to login_attempts"
ON public.login_attempts FOR SELECT
TO anon
USING (false);

-- Fix: Deny anonymous access to scan_reports table  
CREATE POLICY "Deny anonymous access to scan_reports"
ON public.scan_reports FOR SELECT
TO anon
USING (false);

-- Fix: Deny anonymous access to user_roles table
CREATE POLICY "Deny anonymous access to user_roles"
ON public.user_roles FOR SELECT
TO anon
USING (false);

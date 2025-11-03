-- Add missing RLS policies for data management and compliance

-- Allow users to update their own scan reports (e.g., add notes, mark as reviewed)
CREATE POLICY "Users can update own reports"
ON scan_reports FOR UPDATE
USING (auth.uid() = user_id);

-- Allow users to delete their own scan reports (data cleanup)
CREATE POLICY "Users can delete own reports"
ON scan_reports FOR DELETE
USING (auth.uid() = user_id);

-- Allow users to delete their own profile (GDPR/CCPA compliance - right to erasure)
CREATE POLICY "Users can delete own profile"
ON profiles FOR DELETE
USING (auth.uid() = id);

-- Allow admins to manage all scan reports
CREATE POLICY "Admins can manage all reports"
ON scan_reports FOR ALL
USING (has_role(auth.uid(), 'admin'::app_role));

-- Allow admins to delete any profile
CREATE POLICY "Admins can delete all profiles"
ON profiles FOR DELETE
USING (has_role(auth.uid(), 'admin'::app_role));

-- Fix database function search paths for security (addresses linter warning)
-- Update existing functions to set search_path
ALTER FUNCTION has_role(user_id uuid, role app_role) SET search_path = public;
ALTER FUNCTION handle_new_user() SET search_path = public;
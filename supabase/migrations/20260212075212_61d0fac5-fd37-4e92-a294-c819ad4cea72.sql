
-- Fix: attack_learnings unrestricted INSERT policy
DROP POLICY IF EXISTS "System can insert learnings" ON public.attack_learnings;

-- Create policy that validates ownership through attack_attempts
CREATE POLICY "Users can insert learnings for own attacks"
ON public.attack_learnings FOR INSERT
WITH CHECK (
  EXISTS (
    SELECT 1 FROM public.attack_attempts
    WHERE id = attack_attempt_id
    AND user_id = auth.uid()
  )
);

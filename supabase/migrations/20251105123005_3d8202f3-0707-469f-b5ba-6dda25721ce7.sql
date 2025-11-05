-- Ensure full row capturing for realtime updates
ALTER TABLE public.attack_attempts REPLICA IDENTITY FULL;
ALTER TABLE public.attack_chains REPLICA IDENTITY FULL;
ALTER TABLE public.target_intelligence REPLICA IDENTITY FULL;
ALTER TABLE public.attack_learnings REPLICA IDENTITY FULL;

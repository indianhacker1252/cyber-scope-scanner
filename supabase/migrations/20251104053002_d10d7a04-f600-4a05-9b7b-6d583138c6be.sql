-- Create the update_updated_at_column function first
CREATE OR REPLACE FUNCTION public.update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SET search_path = public;

-- Attack Learning and Intelligence System

-- Table to store attack attempts and outcomes
CREATE TABLE public.attack_attempts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
  target TEXT NOT NULL,
  attack_type TEXT NOT NULL,
  technique TEXT NOT NULL,
  payload TEXT,
  success BOOLEAN NOT NULL DEFAULT false,
  output TEXT,
  error_message TEXT,
  metadata JSONB,
  created_at TIMESTAMPTZ DEFAULT now() NOT NULL
);

-- Table to store AI learnings from failed attacks
CREATE TABLE public.attack_learnings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  attack_attempt_id UUID REFERENCES public.attack_attempts(id) ON DELETE CASCADE,
  failure_reason TEXT NOT NULL,
  adaptation_strategy TEXT NOT NULL,
  success_rate DECIMAL DEFAULT 0,
  ai_analysis TEXT,
  created_at TIMESTAMPTZ DEFAULT now() NOT NULL
);

-- Table to store target intelligence
CREATE TABLE public.target_intelligence (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
  target TEXT NOT NULL,
  tech_stack JSONB,
  vulnerabilities JSONB,
  attack_surface JSONB,
  weak_points JSONB,
  ai_recommendations JSONB,
  last_scanned TIMESTAMPTZ DEFAULT now() NOT NULL,
  UNIQUE(user_id, target)
);

-- Table to store autonomous attack chains
CREATE TABLE public.attack_chains (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
  target TEXT NOT NULL,
  chain_name TEXT NOT NULL,
  attack_sequence JSONB NOT NULL,
  status TEXT DEFAULT 'pending',
  current_step INTEGER DEFAULT 0,
  results JSONB,
  created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT now() NOT NULL
);

-- Enable RLS
ALTER TABLE public.attack_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.attack_learnings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.target_intelligence ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.attack_chains ENABLE ROW LEVEL SECURITY;

-- RLS Policies for attack_attempts
CREATE POLICY "Users can view own attack attempts"
ON public.attack_attempts FOR SELECT
USING (auth.uid() = user_id);

CREATE POLICY "Users can create own attack attempts"
ON public.attack_attempts FOR INSERT
WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Admins can view all attack attempts"
ON public.attack_attempts FOR SELECT
USING (has_role(auth.uid(), 'admin'::app_role));

-- RLS Policies for attack_learnings
CREATE POLICY "Users can view learnings from own attacks"
ON public.attack_learnings FOR SELECT
USING (EXISTS (
  SELECT 1 FROM public.attack_attempts 
  WHERE id = attack_attempt_id AND user_id = auth.uid()
));

CREATE POLICY "System can insert learnings"
ON public.attack_learnings FOR INSERT
WITH CHECK (true);

-- RLS Policies for target_intelligence
CREATE POLICY "Users can view own target intelligence"
ON public.target_intelligence FOR SELECT
USING (auth.uid() = user_id);

CREATE POLICY "Users can manage own target intelligence"
ON public.target_intelligence FOR ALL
USING (auth.uid() = user_id);

CREATE POLICY "Admins can view all target intelligence"
ON public.target_intelligence FOR SELECT
USING (has_role(auth.uid(), 'admin'::app_role));

-- RLS Policies for attack_chains
CREATE POLICY "Users can view own attack chains"
ON public.attack_chains FOR SELECT
USING (auth.uid() = user_id);

CREATE POLICY "Users can manage own attack chains"
ON public.attack_chains FOR ALL
USING (auth.uid() = user_id);

CREATE POLICY "Admins can view all attack chains"
ON public.attack_chains FOR SELECT
USING (has_role(auth.uid(), 'admin'::app_role));

-- Trigger for updated_at
CREATE TRIGGER update_attack_chains_updated_at
BEFORE UPDATE ON public.attack_chains
FOR EACH ROW
EXECUTE FUNCTION public.update_updated_at_column();

-- Enable realtime for live attack monitoring
ALTER PUBLICATION supabase_realtime ADD TABLE public.attack_chains;
ALTER PUBLICATION supabase_realtime ADD TABLE public.attack_attempts;
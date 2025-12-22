-- Create apex_successful_chains for long-term knowledge base (without vector type)
CREATE TABLE public.apex_successful_chains (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id UUID NOT NULL,
  target_type TEXT NOT NULL,
  service_signature TEXT,
  vulnerability_type TEXT,
  attack_chain JSONB NOT NULL,
  success_rate DECIMAL(5,2) DEFAULT 0,
  times_used INTEGER DEFAULT 1,
  embedding_data JSONB DEFAULT '[]',
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Enable RLS
ALTER TABLE public.apex_successful_chains ENABLE ROW LEVEL SECURITY;

-- RLS Policies for apex_successful_chains
CREATE POLICY "Users can view their successful chains" ON public.apex_successful_chains FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY "Users can create their successful chains" ON public.apex_successful_chains FOR INSERT WITH CHECK (auth.uid() = user_id);
CREATE POLICY "Users can update their successful chains" ON public.apex_successful_chains FOR UPDATE USING (auth.uid() = user_id);

-- Create indexes for performance
CREATE INDEX idx_apex_successful_chains_user ON public.apex_successful_chains(user_id);
CREATE INDEX idx_apex_successful_chains_service ON public.apex_successful_chains(service_signature);

-- Trigger for updating timestamps
CREATE TRIGGER update_apex_successful_chains_updated_at BEFORE UPDATE ON public.apex_successful_chains FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();
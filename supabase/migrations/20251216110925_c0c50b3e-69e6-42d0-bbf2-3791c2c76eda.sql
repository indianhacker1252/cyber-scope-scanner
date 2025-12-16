-- Create AI learnings table for self-learning capabilities
CREATE TABLE IF NOT EXISTS public.ai_learnings (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id UUID NOT NULL,
  tool_used TEXT NOT NULL,
  target TEXT,
  findings JSONB,
  success BOOLEAN DEFAULT false,
  execution_time INTEGER,
  ai_analysis TEXT,
  improvement_strategy TEXT,
  success_rate NUMERIC DEFAULT 0,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Create AI decisions table to track AI decision making
CREATE TABLE IF NOT EXISTS public.ai_decisions (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id UUID NOT NULL,
  user_input TEXT NOT NULL,
  target TEXT,
  analysis JSONB,
  tools_selected TEXT[],
  execution_results JSONB,
  feedback TEXT,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Enable RLS
ALTER TABLE public.ai_learnings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ai_decisions ENABLE ROW LEVEL SECURITY;

-- Create policies for ai_learnings
CREATE POLICY "Users can view their own learnings" 
ON public.ai_learnings 
FOR SELECT 
USING (auth.uid() = user_id);

CREATE POLICY "Users can create their own learnings" 
ON public.ai_learnings 
FOR INSERT 
WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Service role can manage all learnings"
ON public.ai_learnings
FOR ALL
USING (true)
WITH CHECK (true);

-- Create policies for ai_decisions
CREATE POLICY "Users can view their own decisions" 
ON public.ai_decisions 
FOR SELECT 
USING (auth.uid() = user_id);

CREATE POLICY "Users can create their own decisions" 
ON public.ai_decisions 
FOR INSERT 
WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Service role can manage all decisions"
ON public.ai_decisions
FOR ALL
USING (true)
WITH CHECK (true);

-- Enable realtime for live updates
ALTER PUBLICATION supabase_realtime ADD TABLE public.ai_learnings;
ALTER PUBLICATION supabase_realtime ADD TABLE public.ai_decisions;
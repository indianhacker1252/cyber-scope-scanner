
CREATE TABLE public.mutation_attempts (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id UUID NOT NULL,
  target TEXT NOT NULL,
  parameter TEXT NOT NULL,
  original_payload TEXT NOT NULL,
  mutated_payload TEXT,
  attempt_number INTEGER NOT NULL DEFAULT 1,
  max_retries INTEGER NOT NULL DEFAULT 3,
  http_status INTEGER,
  error_reason TEXT,
  mutation_strategy TEXT,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'firing', 'blocked', 'mutating', 'success', 'defended', 'error')),
  ai_prompt TEXT,
  ai_response TEXT,
  response_body TEXT,
  chain_id UUID,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

ALTER TABLE public.mutation_attempts ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can insert own mutation attempts" ON public.mutation_attempts
  FOR INSERT WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can view own mutation attempts" ON public.mutation_attempts
  FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "Users can update own mutation attempts" ON public.mutation_attempts
  FOR UPDATE USING (auth.uid() = user_id);

ALTER PUBLICATION supabase_realtime ADD TABLE public.mutation_attempts;

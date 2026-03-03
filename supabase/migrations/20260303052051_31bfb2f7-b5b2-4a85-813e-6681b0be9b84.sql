
-- ============================================================
-- Fix: MISSING_RLS on Apex Sentinel tables
-- Creates apex_sessions, apex_tasks, apex_tool_executions, apex_mutation_log
-- with strict user-scoped RLS policies
-- ============================================================

-- 1. apex_sessions
CREATE TABLE IF NOT EXISTS public.apex_sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL,
  session_name TEXT NOT NULL,
  target TEXT NOT NULL,
  target_type TEXT DEFAULT 'domain',
  authorized BOOLEAN DEFAULT false,
  status TEXT DEFAULT 'initializing',
  current_phase TEXT DEFAULT 'reconnaissance',
  target_map JSONB DEFAULT '{}'::jsonb,
  scope_config JSONB DEFAULT '{}'::jsonb,
  attack_chain JSONB DEFAULT '{}'::jsonb,
  findings JSONB DEFAULT '[]'::jsonb,
  constraints JSONB DEFAULT '[]'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE public.apex_sessions ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view own apex sessions"
  ON public.apex_sessions FOR SELECT
  USING (auth.uid() = user_id);

CREATE POLICY "Users can insert own apex sessions"
  ON public.apex_sessions FOR INSERT
  WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update own apex sessions"
  ON public.apex_sessions FOR UPDATE
  USING (auth.uid() = user_id);

CREATE POLICY "Users can delete own apex sessions"
  ON public.apex_sessions FOR DELETE
  USING (auth.uid() = user_id);

CREATE INDEX idx_apex_sessions_user ON public.apex_sessions(user_id);
CREATE INDEX idx_apex_sessions_status ON public.apex_sessions(status);

CREATE TRIGGER update_apex_sessions_updated_at
  BEFORE UPDATE ON public.apex_sessions
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

-- 2. apex_tasks
CREATE TABLE IF NOT EXISTS public.apex_tasks (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id UUID NOT NULL REFERENCES public.apex_sessions(id) ON DELETE CASCADE,
  task_type TEXT NOT NULL DEFAULT 'recon',
  task_name TEXT NOT NULL,
  description TEXT,
  tool_selected TEXT,
  reasoning TEXT,
  priority INTEGER DEFAULT 1,
  status TEXT DEFAULT 'pending',
  mitre_technique TEXT,
  success_probability NUMERIC,
  parent_task_id UUID,
  executed_at TIMESTAMPTZ,
  stdout TEXT,
  stderr TEXT,
  result_analysis JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE public.apex_tasks ENABLE ROW LEVEL SECURITY;

-- Use session ownership to scope task access
CREATE POLICY "Users can view own apex tasks"
  ON public.apex_tasks FOR SELECT
  USING (EXISTS (
    SELECT 1 FROM public.apex_sessions s
    WHERE s.id = apex_tasks.session_id AND s.user_id = auth.uid()
  ));

CREATE POLICY "Users can insert own apex tasks"
  ON public.apex_tasks FOR INSERT
  WITH CHECK (EXISTS (
    SELECT 1 FROM public.apex_sessions s
    WHERE s.id = apex_tasks.session_id AND s.user_id = auth.uid()
  ));

CREATE POLICY "Users can update own apex tasks"
  ON public.apex_tasks FOR UPDATE
  USING (EXISTS (
    SELECT 1 FROM public.apex_sessions s
    WHERE s.id = apex_tasks.session_id AND s.user_id = auth.uid()
  ));

CREATE POLICY "Users can delete own apex tasks"
  ON public.apex_tasks FOR DELETE
  USING (EXISTS (
    SELECT 1 FROM public.apex_sessions s
    WHERE s.id = apex_tasks.session_id AND s.user_id = auth.uid()
  ));

CREATE INDEX idx_apex_tasks_session ON public.apex_tasks(session_id);
CREATE INDEX idx_apex_tasks_status ON public.apex_tasks(status);

CREATE TRIGGER update_apex_tasks_updated_at
  BEFORE UPDATE ON public.apex_tasks
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

-- 3. apex_tool_executions
CREATE TABLE IF NOT EXISTS public.apex_tool_executions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  task_id UUID NOT NULL REFERENCES public.apex_tasks(id) ON DELETE CASCADE,
  session_id UUID NOT NULL REFERENCES public.apex_sessions(id) ON DELETE CASCADE,
  tool_name TEXT NOT NULL,
  command_executed TEXT,
  execution_time_ms INTEGER,
  exit_code INTEGER,
  stdout TEXT,
  stderr TEXT,
  parsed_results JSONB,
  success BOOLEAN DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE public.apex_tool_executions ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view own apex tool executions"
  ON public.apex_tool_executions FOR SELECT
  USING (EXISTS (
    SELECT 1 FROM public.apex_sessions s
    WHERE s.id = apex_tool_executions.session_id AND s.user_id = auth.uid()
  ));

CREATE POLICY "Users can insert own apex tool executions"
  ON public.apex_tool_executions FOR INSERT
  WITH CHECK (EXISTS (
    SELECT 1 FROM public.apex_sessions s
    WHERE s.id = apex_tool_executions.session_id AND s.user_id = auth.uid()
  ));

CREATE INDEX idx_apex_tool_executions_session ON public.apex_tool_executions(session_id);
CREATE INDEX idx_apex_tool_executions_task ON public.apex_tool_executions(task_id);

-- 4. apex_mutation_log
CREATE TABLE IF NOT EXISTS public.apex_mutation_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id UUID NOT NULL REFERENCES public.apex_sessions(id) ON DELETE CASCADE,
  mutation_type TEXT NOT NULL,
  reason TEXT,
  original_payload TEXT,
  mutated_payload TEXT,
  success BOOLEAN DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE public.apex_mutation_log ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view own apex mutation logs"
  ON public.apex_mutation_log FOR SELECT
  USING (EXISTS (
    SELECT 1 FROM public.apex_sessions s
    WHERE s.id = apex_mutation_log.session_id AND s.user_id = auth.uid()
  ));

CREATE POLICY "Users can insert own apex mutation logs"
  ON public.apex_mutation_log FOR INSERT
  WITH CHECK (EXISTS (
    SELECT 1 FROM public.apex_sessions s
    WHERE s.id = apex_mutation_log.session_id AND s.user_id = auth.uid()
  ));

CREATE INDEX idx_apex_mutation_log_session ON public.apex_mutation_log(session_id);

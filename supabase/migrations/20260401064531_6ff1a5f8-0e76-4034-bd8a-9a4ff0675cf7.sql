
CREATE TABLE public.validation_evidence (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL,
  finding_title TEXT NOT NULL,
  finding_severity TEXT NOT NULL DEFAULT 'medium',
  target TEXT NOT NULL,
  vulnerability_type TEXT,
  poc_script TEXT,
  script_language TEXT DEFAULT 'python',
  execution_output TEXT,
  execution_status TEXT DEFAULT 'pending',
  http_request_data JSONB,
  http_response_data JSONB,
  evidence_package JSONB,
  remediation_report TEXT,
  cvss_score NUMERIC(3,1),
  validated_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE public.validation_evidence ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view own validation evidence" ON public.validation_evidence
  FOR SELECT TO authenticated USING (user_id = auth.uid());

CREATE POLICY "Users can insert own validation evidence" ON public.validation_evidence
  FOR INSERT TO authenticated WITH CHECK (user_id = auth.uid());

CREATE POLICY "Users can update own validation evidence" ON public.validation_evidence
  FOR UPDATE TO authenticated USING (user_id = auth.uid());

CREATE TABLE public.audit_agents (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL,
  agent_name TEXT NOT NULL,
  agent_type TEXT NOT NULL DEFAULT 'scanner',
  status TEXT NOT NULL DEFAULT 'active',
  target_endpoint TEXT,
  last_heartbeat TIMESTAMPTZ DEFAULT now(),
  configuration JSONB DEFAULT '{}',
  metrics JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE public.audit_agents ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can manage own audit agents" ON public.audit_agents
  FOR ALL TO authenticated USING (user_id = auth.uid());

ALTER PUBLICATION supabase_realtime ADD TABLE public.audit_agents;

CREATE TRIGGER update_validation_evidence_updated_at BEFORE UPDATE ON public.validation_evidence
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

CREATE TRIGGER update_audit_agents_updated_at BEFORE UPDATE ON public.audit_agents
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

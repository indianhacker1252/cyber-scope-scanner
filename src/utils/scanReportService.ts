import { supabase } from "@/integrations/supabase/client";

export interface ScanReportData {
  target: string;
  scan_type: string;
  vulnerability_name?: string;
  severity?: 'critical' | 'high' | 'medium' | 'low';
  proof_of_concept?: string;
  request_data?: string;
  response_data?: string;
  scan_output?: string;
}

export const saveScanReport = async (reportData: ScanReportData) => {
  try {
    const { data: { user } } = await supabase.auth.getUser();
    
    if (!user) {
      throw new Error('User not authenticated');
    }

    const { data, error } = await supabase
      .from('scan_reports')
      .insert({
        user_id: user.id,
        ...reportData
      })
      .select()
      .single();

    if (error) throw error;
    
    console.log('Scan report saved:', data);
    return { data, error: null };
  } catch (error: any) {
    console.error('Error saving scan report:', error);
    return { data: null, error };
  }
};

export const getScanReports = async (filters?: {
  scan_type?: string;
  severity?: string;
  limit?: number;
}) => {
  try {
    const { data: { user } } = await supabase.auth.getUser();
    
    if (!user) {
      throw new Error('User not authenticated');
    }

    let query = supabase
      .from('scan_reports')
      .select('*')
      .eq('user_id', user.id)
      .order('created_at', { ascending: false });

    if (filters?.scan_type) {
      query = query.eq('scan_type', filters.scan_type);
    }

    if (filters?.severity) {
      query = query.eq('severity', filters.severity);
    }

    if (filters?.limit) {
      query = query.limit(filters.limit);
    }

    const { data, error } = await query;

    if (error) throw error;
    
    return { data, error: null };
  } catch (error: any) {
    console.error('Error fetching scan reports:', error);
    return { data: null, error };
  }
};

export const deleteScanReport = async (reportId: string) => {
  try {
    const { error } = await supabase
      .from('scan_reports')
      .delete()
      .eq('id', reportId);

    if (error) throw error;
    
    return { error: null };
  } catch (error: any) {
    console.error('Error deleting scan report:', error);
    return { error };
  }
};

export type Json =
  | string
  | number
  | boolean
  | null
  | { [key: string]: Json | undefined }
  | Json[]

export type Database = {
  // Allows to automatically instantiate createClient with right options
  // instead of createClient<Database, { PostgrestVersion: 'XX' }>(URL, KEY)
  __InternalSupabase: {
    PostgrestVersion: "13.0.5"
  }
  public: {
    Tables: {
      ai_decisions: {
        Row: {
          analysis: Json | null
          created_at: string
          execution_results: Json | null
          feedback: string | null
          id: string
          target: string | null
          tools_selected: string[] | null
          user_id: string
          user_input: string
        }
        Insert: {
          analysis?: Json | null
          created_at?: string
          execution_results?: Json | null
          feedback?: string | null
          id?: string
          target?: string | null
          tools_selected?: string[] | null
          user_id: string
          user_input: string
        }
        Update: {
          analysis?: Json | null
          created_at?: string
          execution_results?: Json | null
          feedback?: string | null
          id?: string
          target?: string | null
          tools_selected?: string[] | null
          user_id?: string
          user_input?: string
        }
        Relationships: []
      }
      ai_learnings: {
        Row: {
          ai_analysis: string | null
          created_at: string
          execution_time: number | null
          findings: Json | null
          id: string
          improvement_strategy: string | null
          success: boolean | null
          success_rate: number | null
          target: string | null
          tool_used: string
          user_id: string
        }
        Insert: {
          ai_analysis?: string | null
          created_at?: string
          execution_time?: number | null
          findings?: Json | null
          id?: string
          improvement_strategy?: string | null
          success?: boolean | null
          success_rate?: number | null
          target?: string | null
          tool_used: string
          user_id: string
        }
        Update: {
          ai_analysis?: string | null
          created_at?: string
          execution_time?: number | null
          findings?: Json | null
          id?: string
          improvement_strategy?: string | null
          success?: boolean | null
          success_rate?: number | null
          target?: string | null
          tool_used?: string
          user_id?: string
        }
        Relationships: []
      }
      attack_attempts: {
        Row: {
          attack_type: string
          created_at: string
          error_message: string | null
          id: string
          metadata: Json | null
          output: string | null
          payload: string | null
          success: boolean
          target: string
          technique: string
          user_id: string
        }
        Insert: {
          attack_type: string
          created_at?: string
          error_message?: string | null
          id?: string
          metadata?: Json | null
          output?: string | null
          payload?: string | null
          success?: boolean
          target: string
          technique: string
          user_id: string
        }
        Update: {
          attack_type?: string
          created_at?: string
          error_message?: string | null
          id?: string
          metadata?: Json | null
          output?: string | null
          payload?: string | null
          success?: boolean
          target?: string
          technique?: string
          user_id?: string
        }
        Relationships: []
      }
      attack_chains: {
        Row: {
          attack_sequence: Json
          chain_name: string
          created_at: string
          current_step: number | null
          id: string
          results: Json | null
          status: string | null
          target: string
          updated_at: string
          user_id: string
        }
        Insert: {
          attack_sequence: Json
          chain_name: string
          created_at?: string
          current_step?: number | null
          id?: string
          results?: Json | null
          status?: string | null
          target: string
          updated_at?: string
          user_id: string
        }
        Update: {
          attack_sequence?: Json
          chain_name?: string
          created_at?: string
          current_step?: number | null
          id?: string
          results?: Json | null
          status?: string | null
          target?: string
          updated_at?: string
          user_id?: string
        }
        Relationships: []
      }
      attack_learnings: {
        Row: {
          adaptation_strategy: string
          ai_analysis: string | null
          attack_attempt_id: string | null
          created_at: string
          failure_reason: string
          id: string
          success_rate: number | null
        }
        Insert: {
          adaptation_strategy: string
          ai_analysis?: string | null
          attack_attempt_id?: string | null
          created_at?: string
          failure_reason: string
          id?: string
          success_rate?: number | null
        }
        Update: {
          adaptation_strategy?: string
          ai_analysis?: string | null
          attack_attempt_id?: string | null
          created_at?: string
          failure_reason?: string
          id?: string
          success_rate?: number | null
        }
        Relationships: [
          {
            foreignKeyName: "attack_learnings_attack_attempt_id_fkey"
            columns: ["attack_attempt_id"]
            isOneToOne: false
            referencedRelation: "attack_attempts"
            referencedColumns: ["id"]
          },
        ]
      }
      login_attempts: {
        Row: {
          attempted_at: string
          id: string
          ip_address: string | null
          success: boolean
          username: string
        }
        Insert: {
          attempted_at?: string
          id?: string
          ip_address?: string | null
          success?: boolean
          username: string
        }
        Update: {
          attempted_at?: string
          id?: string
          ip_address?: string | null
          success?: boolean
          username?: string
        }
        Relationships: []
      }
      profiles: {
        Row: {
          created_at: string
          display_name: string | null
          id: string
          updated_at: string
          username: string
        }
        Insert: {
          created_at?: string
          display_name?: string | null
          id: string
          updated_at?: string
          username: string
        }
        Update: {
          created_at?: string
          display_name?: string | null
          id?: string
          updated_at?: string
          username?: string
        }
        Relationships: []
      }
      scan_reports: {
        Row: {
          created_at: string
          id: string
          proof_of_concept: string | null
          request_data: string | null
          response_data: string | null
          scan_output: string | null
          scan_type: string
          severity: string | null
          target: string
          user_id: string
          vulnerability_name: string | null
        }
        Insert: {
          created_at?: string
          id?: string
          proof_of_concept?: string | null
          request_data?: string | null
          response_data?: string | null
          scan_output?: string | null
          scan_type: string
          severity?: string | null
          target: string
          user_id: string
          vulnerability_name?: string | null
        }
        Update: {
          created_at?: string
          id?: string
          proof_of_concept?: string | null
          request_data?: string | null
          response_data?: string | null
          scan_output?: string | null
          scan_type?: string
          severity?: string | null
          target?: string
          user_id?: string
          vulnerability_name?: string | null
        }
        Relationships: []
      }
      target_intelligence: {
        Row: {
          ai_recommendations: Json | null
          attack_surface: Json | null
          id: string
          last_scanned: string
          target: string
          tech_stack: Json | null
          user_id: string
          vulnerabilities: Json | null
          weak_points: Json | null
        }
        Insert: {
          ai_recommendations?: Json | null
          attack_surface?: Json | null
          id?: string
          last_scanned?: string
          target: string
          tech_stack?: Json | null
          user_id: string
          vulnerabilities?: Json | null
          weak_points?: Json | null
        }
        Update: {
          ai_recommendations?: Json | null
          attack_surface?: Json | null
          id?: string
          last_scanned?: string
          target?: string
          tech_stack?: Json | null
          user_id?: string
          vulnerabilities?: Json | null
          weak_points?: Json | null
        }
        Relationships: []
      }
      user_roles: {
        Row: {
          id: string
          role: Database["public"]["Enums"]["app_role"]
          user_id: string
        }
        Insert: {
          id?: string
          role?: Database["public"]["Enums"]["app_role"]
          user_id: string
        }
        Update: {
          id?: string
          role?: Database["public"]["Enums"]["app_role"]
          user_id?: string
        }
        Relationships: []
      }
    }
    Views: {
      [_ in never]: never
    }
    Functions: {
      has_role: {
        Args: {
          _role: Database["public"]["Enums"]["app_role"]
          _user_id: string
        }
        Returns: boolean
      }
    }
    Enums: {
      app_role: "admin" | "user"
    }
    CompositeTypes: {
      [_ in never]: never
    }
  }
}

type DatabaseWithoutInternals = Omit<Database, "__InternalSupabase">

type DefaultSchema = DatabaseWithoutInternals[Extract<keyof Database, "public">]

export type Tables<
  DefaultSchemaTableNameOrOptions extends
    | keyof (DefaultSchema["Tables"] & DefaultSchema["Views"])
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
        DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
      DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])[TableName] extends {
      Row: infer R
    }
    ? R
    : never
  : DefaultSchemaTableNameOrOptions extends keyof (DefaultSchema["Tables"] &
        DefaultSchema["Views"])
    ? (DefaultSchema["Tables"] &
        DefaultSchema["Views"])[DefaultSchemaTableNameOrOptions] extends {
        Row: infer R
      }
      ? R
      : never
    : never

export type TablesInsert<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Insert: infer I
    }
    ? I
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Insert: infer I
      }
      ? I
      : never
    : never

export type TablesUpdate<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Update: infer U
    }
    ? U
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Update: infer U
      }
      ? U
      : never
    : never

export type Enums<
  DefaultSchemaEnumNameOrOptions extends
    | keyof DefaultSchema["Enums"]
    | { schema: keyof DatabaseWithoutInternals },
  EnumName extends DefaultSchemaEnumNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"]
    : never = never,
> = DefaultSchemaEnumNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"][EnumName]
  : DefaultSchemaEnumNameOrOptions extends keyof DefaultSchema["Enums"]
    ? DefaultSchema["Enums"][DefaultSchemaEnumNameOrOptions]
    : never

export type CompositeTypes<
  PublicCompositeTypeNameOrOptions extends
    | keyof DefaultSchema["CompositeTypes"]
    | { schema: keyof DatabaseWithoutInternals },
  CompositeTypeName extends PublicCompositeTypeNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"]
    : never = never,
> = PublicCompositeTypeNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"][CompositeTypeName]
  : PublicCompositeTypeNameOrOptions extends keyof DefaultSchema["CompositeTypes"]
    ? DefaultSchema["CompositeTypes"][PublicCompositeTypeNameOrOptions]
    : never

export const Constants = {
  public: {
    Enums: {
      app_role: ["admin", "user"],
    },
  },
} as const

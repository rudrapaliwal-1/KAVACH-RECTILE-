import { request } from "./client";
import type { VibeCIReport, VibeCIStatus } from "./types";

export interface VibeCIVerifyPayload {
  run_static?: boolean;
  run_build?: boolean;
  run_tests?: boolean;
  run_smoke?: boolean;
  changed_only?: boolean;
  compare_ref?: string;
  fail_fast?: boolean;
  timeout_seconds?: number;
}

export const vibeciApi = {
  getStatus(): Promise<VibeCIStatus> {
    return request<VibeCIStatus>("/api/vibeci/status");
  },

  runPreflight(projectId: string): Promise<VibeCIReport> {
    return request<VibeCIReport>(`/api/projects/${encodeURIComponent(projectId)}/vibeci/preflight`, {
      method: "POST",
    });
  },

  runVerification(projectId: string, payload: VibeCIVerifyPayload = {}): Promise<VibeCIReport> {
    return request<VibeCIReport>(`/api/projects/${encodeURIComponent(projectId)}/vibeci/verify`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
  },

  listReports(projectId: string): Promise<Array<{
    id: string;
    project_id: string;
    run_type: string;
    status: string;
    overall_status: string;
    duration_ms: number;
    checks_total: number;
    checks_passed: number;
    checks_failed: number;
    checks_warnings: number;
    checks_unverified: number;
    created_at: string;
  }>> {
    return request(`/api/projects/${encodeURIComponent(projectId)}/vibeci/reports`);
  },

  getReport(projectId: string, runId: string): Promise<{
    id: string;
    project_id: string;
    run_type: string;
    status: string;
    report: VibeCIReport;
    created_at: string;
  }> {
    return request(`/api/projects/${encodeURIComponent(projectId)}/vibeci/reports/${encodeURIComponent(runId)}`);
  },

  getRules(projectId: string): Promise<Record<string, { configured: boolean; path: string }>> {
    return request(`/api/projects/${encodeURIComponent(projectId)}/vibeci/rules`);
  },

  installRules(projectId: string, agent = "all"): Promise<{
    status: string;
    agent: string;
    installed_files: string[];
  }> {
    return request(`/api/projects/${encodeURIComponent(projectId)}/vibeci/rules`, {
      method: "POST",
      body: JSON.stringify({ agent }),
    });
  },
};

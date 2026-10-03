export type ScanSummary = {
  id: string;
  repository: string;
  created_at: string;
  findings_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  scores: Record<string, number>;
};

export type Repository = {
  id: string;
  path: string;
  created_at: string;
  latest_scan: ScanSummary | null;
};

export type Finding = {
  id: string;
  rule_id: string;
  severity: "low" | "medium" | "high";
  confidence: string;
  message: string;
  file: string | null;
  start_line: number | null;
  remediation: string;
};

export type ScanDetail = { findings: Finding[]; scores: Record<string, number> };
export type Rule = { id: string; title: string; severity: string; category: string };
export type Settings = { allowed_roots: string[] };

const baseUrl = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${baseUrl}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...init?.headers },
  });
  if (!response.ok) throw new Error(await response.text());
  return response.json() as Promise<T>;
}

export const api = {
  repositories: () => request<Repository[]>("/api/repositories"),
  scan: (path: string) => request<ScanSummary>("/api/scans", { method: "POST", body: JSON.stringify({ path }) }),
  detail: (id: string) => request<ScanDetail>(`/api/scans/${id}`),
  history: (id: string) => request<ScanSummary[]>(`/api/repositories/${id}/scans`),
  rules: () => request<Rule[]>("/api/rules"),
  settings: () => request<Settings>("/api/settings"),
};

"use client";

import { useMutation, useQuery } from "@tanstack/react-query";
import { FormEvent, useState } from "react";
import { api, Finding, Repository, Rule, ScanDetail, Settings } from "../lib/api";
import { humanizeCategory } from "../lib/format";

const severityClass: Record<Finding["severity"], string> = {
  high: "bg-red-500/20 text-red-300",
  medium: "bg-amber-500/20 text-amber-300",
  low: "bg-sky-500/20 text-sky-300",
};

export function Dashboard() {
  const [path, setPath] = useState("");
  const [selected, setSelected] = useState<Repository | null>(null);
  const repositories = useQuery({ queryKey: ["repositories"], queryFn: api.repositories });
  const runScan = useMutation({ mutationFn: api.scan, onSuccess: () => repositories.refetch() });
  const latest = selected?.latest_scan;
  const detail = useQuery({ queryKey: ["scan", latest?.id], queryFn: () => api.detail(latest!.id), enabled: Boolean(latest) });
  const history = useQuery({ queryKey: ["history", selected?.id], queryFn: () => api.history(selected!.id), enabled: Boolean(selected) });
  const rules = useQuery({ queryKey: ["rules"], queryFn: api.rules });
  const settings = useQuery({ queryKey: ["settings"], queryFn: api.settings });

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (path.trim()) runScan.mutate(path.trim());
  }

  return <main className="mx-auto max-w-7xl p-6">
    <header className="mb-8 flex flex-wrap items-end justify-between gap-4 border-b border-zinc-800 pb-6">
      <div><p className="text-sm text-cyan-400">LOCAL-FIRST DASHBOARD</p><h1 className="text-3xl font-bold">RepoDoctor</h1><p className="mt-2 text-zinc-400">Repository health history, findings and trends.</p></div>
      <form onSubmit={submit} className="flex gap-2"><input value={path} onChange={(event) => setPath(event.target.value)} placeholder="Allowed repository path" className="w-72 rounded border border-zinc-700 bg-zinc-900 px-3 py-2" /><button className="rounded bg-cyan-500 px-4 py-2 font-semibold text-zinc-950 disabled:opacity-50" disabled={runScan.isPending}>Run scan</button></form>
    </header>
    {runScan.error && <p className="mb-4 rounded bg-red-500/20 p-3 text-red-200">{String(runScan.error)}</p>}
    <nav className="mb-4 flex flex-wrap gap-3 text-sm text-zinc-400"><span>Repositories</span><span>Findings</span><span>Rules</span><span>Trends</span><span>Settings</span></nav>
    <section className="grid gap-4 lg:grid-cols-[1fr_2fr]">
      <div className="rounded border border-zinc-800 bg-zinc-950 p-4"><h2 className="mb-3 font-semibold">Repositories</h2>
        {repositories.isLoading ? <p className="text-zinc-400">Loading…</p> : repositories.data?.length ? <ul className="space-y-2">{repositories.data.map((repository) => <li key={repository.id}><button onClick={() => setSelected(repository)} className="w-full rounded border border-zinc-800 p-3 text-left hover:border-cyan-500"><strong className="block truncate">{repository.path}</strong><span className="text-sm text-zinc-400">{repository.latest_scan ? `${repository.latest_scan.findings_count} findings` : "No scans yet"}</span></button></li>)}</ul> : <p className="text-zinc-400">Run a scan to add a repository.</p>}</div>
      <RepositoryPanel repository={selected} detail={detail.data} history={history.data ?? []} />
    </section>
    <section className="mt-4 grid gap-4 lg:grid-cols-2"><RulesPanel rules={rules.data ?? []} /><SettingsPanel settings={settings.data} /></section>
  </main>;
}

function RepositoryPanel({ repository, detail, history }: { repository: Repository | null; detail: ScanDetail | undefined; history: import("../lib/api").ScanSummary[] }) {
  if (!repository || !repository.latest_scan) return <section className="rounded border border-zinc-800 bg-zinc-950 p-6 text-zinc-400">Select a repository with a completed scan.</section>;
  const scan = repository.latest_scan;
  return <section className="space-y-4 rounded border border-zinc-800 bg-zinc-950 p-5"><div><h2 className="text-xl font-semibold">Current health</h2><p className="text-zinc-400">{repository.path}</p></div>
    <div className="grid grid-cols-3 gap-3"><Metric label="High" value={scan.high_count} tone="text-red-300"/><Metric label="Medium" value={scan.medium_count} tone="text-amber-300"/><Metric label="Low" value={scan.low_count} tone="text-sky-300"/></div>
    <div><h3 className="mb-2 font-semibold">Scores</h3><div className="grid gap-2 sm:grid-cols-2">{Object.entries(scan.scores).map(([name, score]) => <div key={name} className="rounded border border-zinc-800 p-3"><span className="text-zinc-400">{humanizeCategory(name)}</span><strong className="float-right">{score}/100</strong></div>)}</div></div>
    <div><h3 className="mb-2 font-semibold">Findings</h3>{detail ? <Findings findings={detail.findings} /> : <p className="text-zinc-400">Loading findings…</p>}</div>
    <div><h3 className="mb-2 font-semibold">Trend</h3><p className="text-zinc-400">{history.length} recorded scan{history.length === 1 ? "" : "s"}; latest has {scan.findings_count} findings.</p></div>
  </section>;
}

function Metric({ label, value, tone }: { label: string; value: number; tone: string }) { return <div className="rounded border border-zinc-800 p-3"><p className="text-sm text-zinc-400">{label}</p><strong className={`text-2xl ${tone}`}>{value}</strong></div>; }

function Findings({ findings }: { findings: Finding[] }) { return <div className="space-y-2">{findings.length ? findings.map((finding) => <article key={finding.id} className="rounded border border-zinc-800 p-3"><div className="flex gap-2"><span className={`rounded px-2 py-0.5 text-xs font-bold ${severityClass[finding.severity]}`}>{finding.severity.toUpperCase()}</span><strong>{finding.rule_id}</strong></div><p className="mt-2">{finding.message}</p><p className="mt-1 text-sm text-zinc-400">{finding.file}{finding.start_line ? `:${finding.start_line}` : ""}</p><p className="mt-2 text-sm text-cyan-200">{finding.remediation}</p></article>) : <p className="text-zinc-400">No findings.</p>}</div>; }

function RulesPanel({ rules }: { rules: Rule[] }) { return <section className="rounded border border-zinc-800 bg-zinc-950 p-5"><h2 className="font-semibold">Rules</h2><p className="mt-1 text-sm text-zinc-400">{rules.length} deterministic built-in rules.</p><div className="mt-3 grid gap-2 sm:grid-cols-2">{rules.slice(0, 6).map((rule) => <div key={rule.id} className="rounded border border-zinc-800 p-2"><strong>{rule.id}</strong><p className="text-sm text-zinc-400">{rule.title}</p></div>)}</div></section>; }

function SettingsPanel({ settings }: { settings: Settings | undefined }) { return <section className="rounded border border-zinc-800 bg-zinc-950 p-5"><h2 className="font-semibold">Settings</h2>{settings ? <><p className="mt-1 text-sm text-zinc-400">Allowed scan roots</p><ul className="mt-2 space-y-1 text-sm">{settings.allowed_roots.map((root) => <li key={root} className="rounded bg-zinc-900 p-2">{root}</li>)}</ul></> : <p className="mt-2 text-zinc-400">Loading API settings…</p>}</section>; }

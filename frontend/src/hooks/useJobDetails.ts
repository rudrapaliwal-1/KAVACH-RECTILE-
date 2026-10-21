import { useCallback, useEffect, useRef, useState } from "react";
import { api, verificationFromEvidence } from "../api/jobs";
import { ApiError } from "../api/client";
import type { Evidence, Job, Patch, SourceResponse, WorkflowEvent } from "../api/types";

export function useJobDetails(id: string | undefined) {
  const [job, setJob] = useState<Job | null>(null);
  const [patch, setPatch] = useState<Patch | null>(null);
  const [events, setEvents] = useState<WorkflowEvent[]>([]);
  const [evidence, setEvidence] = useState<Evidence | null>(null);
  const [source, setSource] = useState<SourceResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const requestId = useRef(0);

  const refresh = useCallback(async () => {
    const sequence = ++requestId.current;
    if (!id) { setLoading(false); return; }
    setError("");
    try {
      const [j, p, ev, evd, src] = await Promise.all([
        api.job(id),
        api.patch(id).catch(error => {
          if (error instanceof ApiError && error.status === 404) return null;
          throw error;
        }),
        api.events(id).catch(() => []),
        api.evidence(id).catch(() => ({} as Evidence)),
        api.source(id).catch(() => null),
      ]);
      if (sequence !== requestId.current) return;
      const runs = (evd?.verification_runs || []) as Array<{ status: string; patch_hash: string }>;
      setJob({
        ...j,
        verification: verificationFromEvidence(evd) || undefined,
        verification_running: runs.some(run => run.status === "RUNNING"),
      });
      setPatch(p);
      setEvents(ev);
      setEvidence(evd);
      setSource(src);
    } catch (e) {
      if (sequence === requestId.current) setError(e instanceof Error ? e.message : "Unable to load investigation");
    } finally {
      if (sequence === requestId.current) setLoading(false);
    }
  }, [id]);

  useEffect(() => {
    void refresh();
    return () => { requestId.current++; };
  }, [refresh]);

  useEffect(() => {
    if (!job || !["FINDING_RECEIVED", "PLANNING", "VERIFYING"].includes(job.status)) return;
    const timer = window.setInterval(() => void refresh(), 3000);
    return () => window.clearInterval(timer);
  }, [job?.status, refresh]);

  return { job, patch, events, evidence, source, loading, error, refresh, setJob, setPatch };
}

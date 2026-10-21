import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import {
  Upload, FolderGit2, Trash2, Search, FileCode2, Sparkles, RefreshCw,
  Play, CheckCircle2, ShieldAlert, ArrowRight, ExternalLink
} from "lucide-react";
import { apiBaseUrl, getCsrfToken, request } from "../api/client";
import { api } from "../api/jobs";

type Project = {
  id: string;
  name: string;
  description: string;
  status: string;
  framework: string | null;
  source_revision: string | null;
  uploaded_at: string | null;
};

type Scan = {
  id: string;
  project_id: string;
  status: string;
  framework: string;
  languages: string[];
  file_count: number;
  finding_count?: number;
  reason: string;
  created_at: string;
};

const finding = {
  id: "BOLA-001",
  type: "BROKEN_OBJECT_LEVEL_AUTHORIZATION",
  severity: "HIGH" as const,
  file_path: "app/access.py",
  description: "A user can access another user's private document through get_document.",
};

function upload(projectId: string, file: File, progress: (value: number) => void): Promise<Project> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open(
      "POST",
      `${apiBaseUrl}/api/projects/${encodeURIComponent(projectId)}/${
        file.name.toLowerCase().endsWith(".zip") ? "upload" : "upload-file"
      }`
    );
    xhr.withCredentials = true;
    xhr.timeout = 120000;
    xhr.setRequestHeader(
      "Content-Type",
      file.name.toLowerCase().endsWith(".zip") ? "application/zip" : "text/plain"
    );
    xhr.setRequestHeader("X-CSRF-Token", getCsrfToken());
    xhr.setRequestHeader(
      file.name.toLowerCase().endsWith(".zip") ? "X-Archive-Name" : "X-File-Name",
      file.name
    );
    xhr.upload.onprogress = event => {
      if (event.lengthComputable) progress(Math.round((event.loaded / event.total) * 100));
    };
    xhr.onload = () => {
      try {
        const value = JSON.parse(xhr.responseText);
        if (xhr.status >= 200 && xhr.status < 300) resolve(value);
        else reject(new Error(value.detail || `Upload failed (${xhr.status})`));
      } catch {
        reject(new Error("Upload returned an invalid response"));
      }
    };
    xhr.onerror = () => reject(new Error("Upload failed: API unavailable"));
    xhr.ontimeout = () => reject(new Error("Upload timed out"));
    xhr.send(file);
  });
}

export default function Projects() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [selected, setSelected] = useState<Project | null>(null);
  const [files, setFiles] = useState<string[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [source, setSource] = useState<{ path: string; content: string } | null>(null);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [zip, setZip] = useState<File | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const fileInput = useRef<HTMLInputElement>(null);
  const [progress, setProgress] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  async function refresh() {
    const rows = await request<Project[]>("/api/projects");
    setProjects(rows);
    if (selected) setSelected(rows.find(row => row.id === selected.id) || null);
  }

  useEffect(() => {
    void refresh().catch(e => setError(e instanceof Error ? e.message : "Could not load projects"));
  }, []);

  async function useDemoRepository() {
    setError("");
    setMessage("");
    try {
      const response = await fetch("/sentinel-bola-demo.zip");
      if (!response.ok) throw new Error("Demo repository ZIP is unavailable.");
      const archive = await response.blob();
      fileInput.current && (fileInput.current.value = "");
      setZip(new File([archive], "sentinel-bola-demo.zip", { type: "application/zip" }));
      if (!name.trim()) setName("KAVACH-X BOLA demo");
      setMessage("Demo repository selected. Upload it to run the supported BOLA workflow.");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not load the demo repository.");
    }
  }

  async function create() {
    if (!zip) {
      setError("Select a ZIP or source file first.");
      return;
    }
    setBusy(true);
    setError("");
    setMessage("");
    setProgress(0);
    try {
      const project = await request<Project>("/api/projects", {
        method: "POST",
        body: JSON.stringify({ name, description }),
      });
      const imported = await upload(project.id, zip, setProgress);
      setSelected(imported);
      setZip(null);
      setName("");
      setDescription("");
      await refresh();
      setMessage(
        imported.status === "SUPPORTED_BOLA_CONTRACT"
          ? "BOLA example uploaded. Static scanning and protected remediation are available."
          : imported.status === "READY_FOR_SCAN"
          ? "Source uploaded. Start a static security scan to review potential findings."
          : "Uploaded format has no supported analysis language."
      );
      setFiles(await request<string[]>(`/api/projects/${project.id}/files`));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Project upload failed");
      await refresh();
    } finally {
      setBusy(false);
    }
  }

  async function select(project: Project) {
    setSelected(project);
    setSource(null);
    setError("");
    try {
      setFiles(await request<string[]>(`/api/projects/${project.id}/files`));
      setScans(await request<Scan[]>(`/api/projects/${project.id}/scans`));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not load files");
    }
  }

  async function startScan() {
    if (!selected) return;
    setBusy(true);
    setError("");
    try {
      const result = await request<Scan>(
        `/api/projects/${selected.id}/scan`,
        { method: "POST" },
        30000
      );
      setScans(await request<Scan[]>(`/api/projects/${selected.id}/scans`));
      setMessage(
        result.status === "UNSUPPORTED"
          ? result.reason
          : `Scan complete: ${result.finding_count || 0} potential findings. Review them on the Findings page.`
      );
    } catch (e) {
      setError(e instanceof Error ? e.message : "Scan failed");
    } finally {
      setBusy(false);
    }
  }

  async function startFinding() {
    if (!selected) return;
    setBusy(true);
    setError("");
    try {
      const result = await api.createFinding({ target_app_id: selected.id, finding });
      setMessage(`Finding supplied and AI remediation started. Job ${result.job_id}`);
      window.location.assign(`/jobs/${result.job_id}`);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not start remediation");
    } finally {
      setBusy(false);
    }
  }

  async function deleteProject(id: string) {
    if (!window.confirm("Are you sure you want to delete this project? This will remove its extracted source files.")) return;
    setBusy(true);
    setError("");
    setMessage("");
    try {
      await request(`/api/projects/${encodeURIComponent(id)}`, { method: "DELETE" });
      setMessage("Project deleted successfully.");
      if (selected?.id === id) {
        setSelected(null);
        setFiles([]);
        setScans([]);
        setSource(null);
      }
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to delete project");
    } finally {
      setBusy(false);
    }
  }

  async function cleanDrafts() {
    const drafts = projects.filter(p => p.status === "CREATED" && !p.source_revision);
    if (!drafts.length) return;
    if (!window.confirm(`Delete ${drafts.length} empty unuploaded draft projects?`)) return;
    setBusy(true);
    setError("");
    setMessage("");
    try {
      for (const d of drafts) {
        await request(`/api/projects/${encodeURIComponent(d.id)}`, { method: "DELETE" });
      }
      setMessage(`Cleaned ${drafts.length} empty draft projects.`);
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to clean draft projects");
    } finally {
      setBusy(false);
    }
  }

  const filteredProjects = projects.filter(p =>
    `${p.name} ${p.id} ${p.framework || ""} ${p.status}`
      .toLowerCase()
      .includes(searchQuery.toLowerCase())
  );

  const draftCount = projects.filter(p => p.status === "CREATED" && !p.source_revision).length;

  return (
    <div className="page">
      <div className="page-heading">
        <div>
          <div className="eyebrow">SOURCE ONBOARDING</div>
          <h1>Projects</h1>
          <p>Upload a ZIP repository or source file, run a static scan, and review potential findings.</p>
        </div>
      </div>

      {/* Upload Repository Panel */}
      <section className="panel create-panel">
        <div className="panel-heading">
          <h2><FolderGit2 size={16} /> New Project → Upload Repository</h2>
        </div>
        <div className="project-form">
          <div className="project-form-grid" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
            <div className="form-group">
              <label htmlFor="project-name">Project Name</label>
              <input
                id="project-name"
                value={name}
                maxLength={100}
                onChange={e => setName(e.target.value)}
                placeholder="e.g. My FastAPI Project"
              />
            </div>
            <div className="form-group">
              <label htmlFor="project-desc">Description (Optional)</label>
              <input
                id="project-desc"
                value={description}
                maxLength={1000}
                onChange={e => setDescription(e.target.value)}
                placeholder="Brief description of this repository"
              />
            </div>
          </div>

          <div className="form-group">
            <label htmlFor="project-archive">Repository ZIP or Source Archive</label>
            <div className="file-input-card">
              <input
                id="project-archive"
                ref={fileInput}
                type="file"
                accept=".zip,.py,.js,.jsx,.ts,.tsx"
                onChange={e => {
                  const f = e.target.files?.[0] || null;
                  setZip(f);
                  if (f && !name.trim()) {
                    setName(f.name.replace(/\.[^/.]+$/, ""));
                  }
                  setMessage("");
                  setError("");
                }}
              />
            </div>
          </div>

          <div className="project-form-actions">
            <button
              className="button button-lime"
              disabled={busy || !name.trim() || !zip}
              onClick={() => void create()}
            >
              <Upload size={14} />
              {busy ? "Uploading…" : "Upload Repository"}
            </button>
            <button
              className="button button-orbit"
              disabled={busy}
              onClick={() => void useDemoRepository()}
            >
              <Sparkles size={14} />
              Use demo repository
            </button>
            <a className="button button-ghost-sm" href="/sentinel-bola-demo.zip" download>
              Download demo ZIP
            </a>
          </div>

          {zip && (
            <p className="project-file-name" role="status">
              Selected archive: <strong>{zip.name}</strong>
            </p>
          )}
          {busy && <p className="project-file-name" role="status">Upload progress: {progress}%</p>}
          {!name.trim() || !zip ? (
            <p className="project-file-hint">
              {!zip ? "Choose a ZIP or source file to enable upload." : "Enter a project name to enable upload."}
            </p>
          ) : null}
          <p className="fine-print">
            Static scans never execute uploaded code. Findings are potential matches requiring review.
            The BOLA demo has a separate protected remediation workflow. Source is never sent to AI during upload or static scan.
          </p>
        </div>
      </section>

      {error && <div className="error-banner" role="alert">{error}</div>}
      {message && <div className="notice wide" role="status">{message}</div>}

      {/* Projects List Panel */}
      <section className="panel">
        <div className="panel-heading">
          <div>
            <div className="eyebrow">TARGET REPOSITORIES</div>
            <h2>Your projects <span className="subtle-count">{projects.length}</span></h2>
          </div>
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            {draftCount > 1 && (
              <button
                className="button button-ghost-sm"
                onClick={() => void cleanDrafts()}
                disabled={busy}
                title="Remove unuploaded draft projects"
              >
                Clean {draftCount} drafts
              </button>
            )}
            <button className="button button-secondary" onClick={() => void refresh()} disabled={busy}>
              <RefreshCw size={13} /> Refresh
            </button>
          </div>
        </div>

        {/* Search bar inside panel */}
        <div className="table-tools">
          <div className="input-search">
            <Search size={14} />
            <input
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              placeholder="Filter projects by name, framework, status…"
            />
          </div>
        </div>

        {projects.length === 0 ? (
          <div className="empty-state">
            <FolderGit2 size={24} />
            <strong>No projects uploaded yet</strong>
            <span>Upload a repository ZIP or use the demo repository to get started.</span>
          </div>
        ) : filteredProjects.length === 0 ? (
          <div className="empty-state">
            <Search size={20} />
            <span>No projects match "{searchQuery}".</span>
          </div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Project Name</th>
                  <th>Status</th>
                  <th>Framework</th>
                  <th>Source Digest</th>
                  <th>Uploaded</th>
                  <th style={{ textAlign: "right" }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredProjects.map(project => (
                  <tr
                    key={project.id}
                    style={selected?.id === project.id ? { background: "rgba(183, 243, 107, 0.05)" } : undefined}
                  >
                    <td>
                      <strong style={{ color: "var(--warm-paper)" }}>{project.name}</strong>
                      <div style={{ fontSize: 11, color: "var(--text-faint)", fontFamily: "'JetBrains Mono', monospace" }}>
                        {project.id}
                      </div>
                    </td>
                    <td>
                      <span
                        className={`badge ${
                          project.status === "SUPPORTED_BOLA_CONTRACT"
                            ? "success"
                            : project.status === "READY_FOR_SCAN"
                            ? "info"
                            : "muted"
                        }`}
                      >
                        {project.status === "SUPPORTED_BOLA_CONTRACT" && <CheckCircle2 size={11} />}
                        {project.status}
                      </span>
                    </td>
                    <td>{project.framework || <span style={{ color: "var(--text-faint)" }}>Pending detection</span>}</td>
                    <td>
                      <code style={{ fontSize: 11 }}>
                        {project.source_revision ? project.source_revision.slice(0, 18) + "…" : "Pending"}
                      </code>
                    </td>
                    <td className="date-cell">
                      {project.uploaded_at ? new Date(project.uploaded_at).toLocaleString() : "—"}
                    </td>
                    <td style={{ textAlign: "right" }}>
                      <div style={{ display: "inline-flex", gap: 6, alignItems: "center" }}>
                        <button
                          className={`button ${selected?.id === project.id ? "button-lime" : "button-secondary"}`}
                          style={{ padding: "4px 10px", fontSize: 11 }}
                          onClick={() => void select(project)}
                        >
                          {selected?.id === project.id ? "Selected" : "Inspect"}
                        </button>
                        <button
                          className="table-action"
                          style={{ color: "var(--threat-coral)" }}
                          disabled={busy}
                          onClick={() => void deleteProject(project.id)}
                          title="Delete project"
                        >
                          <Trash2 size={13} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Selected Project Details */}
      {selected && (
        <section className="panel">
          <div className="panel-heading">
            <div>
              <div className="eyebrow">SELECTED TARGET</div>
              <h2>{selected.name}</h2>
            </div>
            <span
              className={`badge ${
                selected.status === "SUPPORTED_BOLA_CONTRACT"
                  ? "success"
                  : selected.status === "READY_FOR_SCAN"
                  ? "info"
                  : "muted"
              }`}
            >
              {selected.status}
            </span>
          </div>
          <div style={{ padding: "18px 24px" }}>
            <p style={{ color: "var(--text-muted)", marginBottom: 12 }}>{selected.description || "No description provided."}</p>
            <div style={{ display: "flex", gap: 20, flexWrap: "wrap", fontSize: 12, marginBottom: 16 }}>
              <div>Framework: <strong>{selected.framework || "Pending detection"}</strong></div>
              <div>Source Revision: <code>{selected.source_revision || "Unavailable"}</code></div>
            </div>

            <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginBottom: 16 }}>
              <button
                className="button button-lime"
                disabled={busy || selected.status === "UNSUPPORTED"}
                onClick={() => void startScan()}
              >
                <Play size={13} /> Start static security scan
              </button>
            </div>

            {selected.status === "SUPPORTED_BOLA_CONTRACT" && (
              <div
                style={{
                  background: "rgba(183, 243, 107, 0.08)",
                  padding: 16,
                  borderRadius: 10,
                  margin: "16px 0",
                  border: "1px solid rgba(183, 243, 107, 0.25)",
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: 8, color: "var(--signal-lime)", fontWeight: 700, marginBottom: 6 }}>
                  <ShieldAlert size={16} /> Supported BOLA Target
                </div>
                <p style={{ fontSize: 12, color: "var(--warm-paper)", margin: "0 0 12px" }}>
                  Broken Object Level Authorization in <code>app/access.py</code>. Confirm this finding applies to a repository you are authorized to test.
                </p>
                <button className="button button-lime" disabled={busy} onClick={() => void startFinding()}>
                  Select BOLA finding and generate AI fix
                </button>
              </div>
            )}

            <h3 style={{ fontSize: 14, fontWeight: 700, margin: "20px 0 10px" }}>Scan History</h3>
            {scans.length ? (
              <div className="table-wrap" style={{ margin: "10px 0 16px" }}>
                <table>
                  <thead>
                    <tr>
                      <th>Status</th>
                      <th>Findings</th>
                      <th>Framework</th>
                      <th>Scanned At</th>
                      <th>Reason / Notes</th>
                      <th>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {scans.map(scan => (
                      <tr key={scan.id}>
                        <td>
                          <span
                            className={`badge ${
                              scan.status === "READY_FOR_SCAN" || scan.status === "SUPPORTED"
                                ? "success"
                                : "muted"
                            }`}
                          >
                            {scan.status}
                          </span>
                        </td>
                        <td>
                          <strong style={{ color: "var(--signal-lime)" }}>{scan.finding_count ?? 0}</strong> findings
                        </td>
                        <td>{scan.framework}</td>
                        <td className="date-cell">{new Date(scan.created_at).toLocaleString()}</td>
                        <td><small style={{ color: "var(--text-muted)" }}>{scan.reason}</small></td>
                        <td>
                          <Link className="button button-ghost-sm" to="/findings">
                            View findings <ArrowRight size={12} />
                          </Link>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <p style={{ fontSize: 12, color: "var(--text-faint)", margin: "6px 0 16px" }}>No static scans executed yet.</p>
            )}

            <h3 style={{ fontSize: 14, fontWeight: 700, margin: "20px 0 10px" }}>Source Files</h3>
            <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 16 }}>
              {files.map(path => (
                <button
                  key={path}
                  className="button button-secondary"
                  style={{ padding: "4px 10px", fontSize: 11 }}
                  onClick={() =>
                    void request<{ path: string; content: string }>(
                      `/api/projects/${selected.id}/files/${path.split("/").map(encodeURIComponent).join("/")}`
                    )
                      .then(setSource)
                      .catch(e => setError(e.message))
                  }
                >
                  <FileCode2 size={12} /> {path}
                </button>
              ))}
            </div>

            {source && (
              <div style={{ marginTop: 12, background: "rgba(0,0,0,0.3)", borderRadius: 8, padding: 12 }}>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8, fontSize: 12 }}>
                  <code>{source.path}</code>
                </div>
                <pre style={{ overflow: "auto", maxHeight: 400, fontSize: 12, fontFamily: "'JetBrains Mono', monospace" }}>
                  {source.content}
                </pre>
              </div>
            )}

            <p style={{ marginTop: 18 }}>
              <Link to="/findings" className="button button-ghost-sm" style={{ display: "inline-flex", gap: 6, alignItems: "center" }}>
                View security findings <ExternalLink size={12} />
              </Link>
            </p>
          </div>
        </section>
      )}
    </div>
  );
}

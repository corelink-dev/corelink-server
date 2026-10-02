// Customer-side "Workspaces" (W10) — clw snapshots + Pin, now backed by a LIVE
// backend (BE-11).
//
// DATA-TRUTH (mirrors customer_d1.rs / customer-types.ts):
//   listWorkspaces / createWorkspace / deleteWorkspace / pinWorkspace .. [live] (BE-11)
//
// Kit-only: every surface is a `@/components/ui/linear` primitive. CRUD fires a
// Toast; delete is gated behind a `ConfirmDialog` (danger). No-data renders a
// teaching EmptyState (never a fabricated row); load failure renders InlineError.
// One concise explainer (the prior duplicated two-card prose wall is removed).

"use client";

import React from "react";
import { useCustomerClient } from "@/lib/use-customer-client";
import type { CustomerWorkspace } from "@/lib/customer-types";
import {
  Badge,
  Button,
  Callout,
  Card,
  ConfirmDialog,
  EmptyState,
  Field,
  HelpPopover,
  InlineError,
  Input,
  Skeleton,
  ToastProvider,
  useToast,
} from "@/components/ui/linear";

/** Humanize a byte count into KB/MB/GB (binary units, 1024). Renders an honest
 *  "0 B" for empty snapshots — never a fabricated size. */
function humanizeBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
  const value = bytes / 1024 ** i;
  const rounded = i === 0 ? value : Math.round(value * 10) / 10;
  return `${rounded} ${units[i]}`;
}

function WorkspacesInner(): React.ReactElement {
  const client = useCustomerClient();
  const { toast } = useToast();

  const [workspaces, setWorkspaces] = React.useState<CustomerWorkspace[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState<unknown | null>(null);

  const [draftName, setDraftName] = React.useState("");
  const [creating, setCreating] = React.useState(false);
  const [pinningId, setPinningId] = React.useState<string | null>(null);
  const [deleteTarget, setDeleteTarget] = React.useState<CustomerWorkspace | null>(null);

  const reload = React.useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const r = await client.listWorkspaces();
      setWorkspaces(r.workspaces);
    } catch (e) {
      setError(e);
    } finally {
      setLoading(false);
    }
  }, [client]);

  React.useEffect(() => {
    void reload();
  }, [reload]);

  async function onCreate(e: React.FormEvent): Promise<void> {
    e.preventDefault();
    if (creating) return;
    const name = draftName.trim();
    if (!name) return;
    setCreating(true);
    try {
      const ws = await client.createWorkspace({ name });
      setDraftName("");
      toast({ title: `Workspace "${ws.name}" created`, tone: "success" });
      await reload();
    } catch (ex) {
      setError(ex);
      toast({ title: "Couldn't create workspace", tone: "danger" });
    } finally {
      setCreating(false);
    }
  }

  async function onTogglePin(ws: CustomerWorkspace): Promise<void> {
    if (pinningId) return;
    setPinningId(ws.workspace_id);
    try {
      const updated = await client.pinWorkspace(ws.workspace_id, !ws.pinned);
      toast({
        title: updated.pinned
          ? `Pinned "${updated.name}"`
          : `Unpinned "${updated.name}"`,
        tone: "success",
      });
      await reload();
    } catch (ex) {
      setError(ex);
      toast({ title: "Couldn't update pin", tone: "danger" });
    } finally {
      setPinningId(null);
    }
  }

  async function onConfirmDelete(): Promise<void> {
    const target = deleteTarget;
    if (!target) return;
    try {
      await client.deleteWorkspace(target.workspace_id);
      toast({ title: `Workspace "${target.name}" deleted`, tone: "success" });
      await reload();
    } catch (ex) {
      setError(ex);
      toast({ title: "Couldn't delete workspace", tone: "danger" });
    }
  }

  const pinnedCount = workspaces.filter((w) => w.pinned).length;

  return (
    <div data-testid="workspaces-shell">
      {/* ── One concise explainer (replaces the old two-card prose wall) ── */}
      <Card
        title="Workspaces & pinning"
        actions={
          <HelpPopover label="What is a workspace?">
            A workspace is a captured working tree — your repo checkout plus its
            build state — that <code>clw</code> uploads once and can restore
            anywhere. It writes into content-addressed storage, so unchanged
            content is deduplicated and only new bytes are uploaded.
          </HelpPopover>
        }
      >
        <p className="lin-card__meta">
          <strong>Snapshot</strong>{" "}
          <HelpPopover label="What is a snapshot?">
            A snapshot writes your workspace into content-addressed storage — every
            file is stored by its hash, so unchanged content is deduplicated. Push
            one with <code>clw snapshot</code>.
          </HelpPopover>{" "}
          a workspace to content-addressed storage and{" "}
          <strong>hydrate</strong>{" "}
          <HelpPopover label="What is hydrate?">
            Hydrating restores a snapshot into a working directory. Because the
            content is already cached and deduplicated, a fresh machine or runner
            reconstructs the tree in seconds instead of re-cloning and rebuilding.
          </HelpPopover>{" "}
          it onto any machine in seconds — no re-clone, no cold rebuild.{" "}
          <strong>Pin</strong>{" "}
          <HelpPopover label="What is Pin?">
            Pin records a durable retention preference for this snapshot. It does
            not currently guarantee residency, change eviction, or change billing;
            there is no metered add-on promise here.
          </HelpPopover>{" "}
          the ones your team hydrates most so the retention preference is recorded.
        </p>
      </Card>

      {/* ── Create ─────────────────────────────────────────────────────── */}
      <Card title="New workspace" className="lin-mt-lg">
        <form data-testid="workspaces-create" onSubmit={onCreate}>
          <Field
            label="Workspace name"
            htmlFor="workspaces-create-name"
            help="A label to recognize this snapshot later (e.g. 'main-nightly' or 'release-1.4')."
          >
            <Input
              id="workspaces-create-name"
              data-testid="workspaces-create-name"
              required
              placeholder="main-nightly"
              value={draftName}
              onChange={(e) => setDraftName(e.target.value)}
            />
          </Field>
          <div className="lin-mt">
            <Button
              type="submit"
              data-testid="workspaces-create-submit"
              loading={creating}
              disabled={draftName.trim().length === 0}
            >
              Create workspace
            </Button>
          </div>
        </form>
      </Card>

      {/* ── List ───────────────────────────────────────────────────────── */}
      <Card
        title="Your workspaces"
        meta={
          !loading && error == null && workspaces.length > 0
            ? `${workspaces.length} snapshot${workspaces.length === 1 ? "" : "s"} · ${pinnedCount} pinned`
            : undefined
        }
        className="lin-mt-lg"
      >
        {loading ? (
          <div data-testid="workspaces-loading" aria-busy="true" aria-label="Loading workspaces">
            <Skeleton rows={3} />
          </div>
        ) : error != null ? (
          <InlineError error={error} onRetry={() => void reload()} />
        ) : workspaces.length === 0 ? (
          <div data-testid="workspaces-list-empty">
            <EmptyState
              title="No workspaces yet — create one to snapshot your cache state"
              body="Push a snapshot with the clw CLI, or create one above. Your workspace uploads to content-addressed storage and shows up here, ready to hydrate anywhere."
              cta={
                <div data-testid="workspaces-list-cta">
                  <Button
                    onClick={() => {
                      document.getElementById("workspaces-create-name")?.focus();
                    }}
                  >
                    Create workspace
                  </Button>
                </div>
              }
            />
          </div>
        ) : (
          <table className="lin-table" data-testid="workspaces-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Size</th>
                <th>Created</th>
                <th>Pinned</th>
                <th aria-label="Actions" />
              </tr>
            </thead>
            <tbody>
              {workspaces.map((ws) => (
                <tr key={ws.workspace_id} data-testid={`workspaces-row-${ws.workspace_id}`}>
                  <td>{ws.name}</td>
                  <td>{humanizeBytes(ws.size_bytes)}</td>
                  <td>{ws.created_at.slice(0, 10)}</td>
                  <td data-testid={`workspaces-pinned-${ws.workspace_id}`}>
                    {ws.pinned ? (
                      <Badge tone="success" dot>
                        Pinned
                      </Badge>
                    ) : (
                      <span className="lin-t3">Not pinned</span>
                    )}
                  </td>
                  <td>
                    <div className="lin-card__actions">
                      <Button
                        variant="ghost"
                        size="sm"
                        data-testid={`workspaces-pin-${ws.workspace_id}`}
                        loading={pinningId === ws.workspace_id}
                        disabled={pinningId != null && pinningId !== ws.workspace_id}
                        onClick={() => void onTogglePin(ws)}
                      >
                        {ws.pinned ? "Unpin" : "Pin"}
                      </Button>
                      <Button
                        variant="danger"
                        size="sm"
                        data-testid={`workspaces-delete-${ws.workspace_id}`}
                        onClick={() => setDeleteTarget(ws)}
                      >
                        Delete
                      </Button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>

      {/* ── Delete confirmation ────────────────────────────────────────── */}
      <ConfirmDialog
        open={deleteTarget != null}
        title="Delete this workspace?"
        danger
        confirmLabel="Delete workspace"
        body={
          deleteTarget ? (
            <Callout tone="danger">
              Delete <strong>{deleteTarget.name}</strong>? Its snapshot is removed
              and can no longer be hydrated. Deduplicated content shared with other
              snapshots is kept; unique bytes are freed. This can&apos;t be undone.
            </Callout>
          ) : null
        }
        onClose={() => setDeleteTarget(null)}
        onConfirm={onConfirmDelete}
      />
    </div>
  );
}

/** Public entry — wraps the screen in a local ToastProvider so `useToast` works
 *  even when this client is mounted bare (nested providers are harmless — the
 *  innermost wins). Mirrors KeysClient. */
export function WorkspacesClient(): React.ReactElement {
  return (
    <ToastProvider>
      <WorkspacesInner />
    </ToastProvider>
  );
}

export default WorkspacesClient;

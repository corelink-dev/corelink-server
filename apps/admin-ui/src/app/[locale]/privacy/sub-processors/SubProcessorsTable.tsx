"use client";

import * as React from "react";
import type { Locale } from "@/i18n/LocaleContext";
import type { SubProcessor } from "@/content/load";

/**
 * SubProcessorsTable — Linear-doctrine (`.lin-table`) table for the public
 * sub-processors register. The shared `@/components/ui/Table` is hard
 * light-themed (`bg-slate-50` / `text-slate-900`, no override) and would render
 * dark-on-dark on the public shell, so this surface-specific table applies the
 * frozen kit table styles with token colours. Semantics preserved: `role=table`
 * with an accessible name from `<caption>`, and per-column sort `<button>`s for
 * the sortable columns (name / region).
 *
 * Each row links the vendor's own standard terms and DPA — the contract basis
 * for every listed sub-processor (B-316 owner re-charter, #2593). No dates are
 * shown: online acceptance dates were not recorded.
 */
export interface SubProcessorsTableProps {
  locale: Locale;
  caption: string;
  headers: {
    name: string;
    role: string;
    region: string;
    certs: string;
    terms: string;
    dpa: string;
    termsLink: string;
    dpaLink: string;
  };
  items: SubProcessor[];
}

type SortKey = "name" | "region";

export function SubProcessorsTable({
  caption,
  headers,
  items,
}: SubProcessorsTableProps): React.ReactElement {
  const [sortKey, setSortKey] = React.useState<SortKey | null>(null);
  const [asc, setAsc] = React.useState(true);

  const sorted = React.useMemo(() => {
    if (sortKey == null) return items;
    const copy = [...items];
    copy.sort((a, b) => {
      const av = String(a[sortKey]);
      const bv = String(b[sortKey]);
      return asc ? av.localeCompare(bv) : bv.localeCompare(av);
    });
    return copy;
  }, [items, sortKey, asc]);

  function onSort(key: SortKey) {
    if (sortKey === key) setAsc((v) => !v);
    else {
      setSortKey(key);
      setAsc(true);
    }
  }

  function ariaSort(key: SortKey): "ascending" | "descending" | "none" {
    if (sortKey !== key) return "none";
    return asc ? "ascending" : "descending";
  }

  function SortButton({ label, sortKey: key }: { label: string; sortKey: SortKey }) {
    return (
      <button
        type="button"
        onClick={() => onSort(key)}
        className="inline-flex items-center gap-1 text-[var(--t3)] underline-offset-2 transition-colors hover:text-[var(--t1)] hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--line-2)]"
      >
        {label}
        <span aria-hidden="true">
          {sortKey === key && (asc ? "↑" : "↓")}
        </span>
      </button>
    );
  }

  const linkClass =
    "text-[var(--t1)] underline underline-offset-2 hover:text-[var(--t2)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--line-2)]";

  // A vendor page that could not be confirmed is published as the literal
  // "link pending" (never a guessed URL); render it as text, not a link.
  function VendorLink({ href, label, vendor }: { href: string; label: string; vendor: string }) {
    if (!href.startsWith("https://")) return <span>{href}</span>;
    return (
      <a
        href={href}
        target="_blank"
        rel="noopener noreferrer"
        className={linkClass}
        aria-label={`${label} — ${vendor}`}
      >
        {label}
      </a>
    );
  }

  return (
    <table className="lin-table">
      <caption className="sr-only">{caption}</caption>
      <thead>
        <tr>
          <th scope="col" aria-sort={ariaSort("name")}>
            <SortButton label={headers.name} sortKey="name" />
          </th>
          <th scope="col">{headers.role}</th>
          <th scope="col" aria-sort={ariaSort("region")}>
            <SortButton label={headers.region} sortKey="region" />
          </th>
          <th scope="col">{headers.certs}</th>
          <th scope="col">{headers.terms}</th>
          <th scope="col">{headers.dpa}</th>
        </tr>
      </thead>
      <tbody>
        {sorted.map((row) => (
          <tr key={row.id}>
            <td className="text-[var(--t1)]">{row.name}</td>
            <td>{row.role}</td>
            <td>{row.region}</td>
            <td>{row.certifications.join(", ")}</td>
            <td>
              <VendorLink href={row.terms_url} label={headers.termsLink} vendor={row.name} />
            </td>
            <td>
              <VendorLink href={row.dpa_url} label={headers.dpaLink} vendor={row.name} />
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export default SubProcessorsTable;

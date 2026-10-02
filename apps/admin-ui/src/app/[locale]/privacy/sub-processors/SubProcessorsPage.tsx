"use client";

import * as React from "react";
import { PublicShell } from "@/components/public/PublicShell";
import { PublicPageHeader } from "@/components/public/PublicPageHeader";
import { Button } from "@/components/ui/linear";
import { SubProcessorsTable } from "./SubProcessorsTable";
import type { Locale } from "@/i18n/LocaleContext";
import type { SubProcessor } from "@/content/load";

// R-prep i18n-de — `de` joined as the fourth canonical locale.
const TITLE: Record<Locale, string> = {
  en: "Sub-processors",
  pt: "Subprocessadores",
  es: "Subprocesadores",
  de: "Unterauftragsverarbeiter",
};

type Headers = {
  name: string;
  role: string;
  region: string;
  certs: string;
  terms: string;
  dpa: string;
  termsLink: string;
  dpaLink: string;
  download: string;
};

// Each vendor is engaged on its own standard terms and DPA (B-316 owner
// re-charter, #2593); the table links both. No acceptance dates are shown
// because none were recorded.
const HEADERS: Record<Locale, Headers> = {
  en: {
    name: "Name",
    role: "Role",
    region: "Region",
    certs: "Certifications",
    terms: "Terms",
    dpa: "DPA",
    termsLink: "Vendor terms",
    dpaLink: "Vendor DPA",
    download: "Download CSV",
  },
  pt: {
    name: "Nome",
    role: "Função",
    region: "Região",
    certs: "Certificações",
    terms: "Termos",
    dpa: "DPA",
    termsLink: "Termos do fornecedor",
    dpaLink: "DPA do fornecedor",
    download: "Baixar CSV",
  },
  es: {
    name: "Nombre",
    role: "Función",
    region: "Región",
    certs: "Certificaciones",
    terms: "Términos",
    dpa: "DPA",
    termsLink: "Términos del proveedor",
    dpaLink: "DPA del proveedor",
    download: "Descargar CSV",
  },
  de: {
    name: "Name",
    role: "Rolle",
    region: "Region",
    certs: "Zertifizierungen",
    terms: "Bedingungen",
    dpa: "AVV (DPA)",
    termsLink: "Bedingungen des Anbieters",
    dpaLink: "AVV des Anbieters",
    download: "CSV herunterladen",
  },
};

export interface SubProcessorsPageProps {
  locale: Locale;
  version: string;
  items: SubProcessor[];
}

function toCsv(items: SubProcessor[]): string {
  const header = ["id", "name", "role", "region", "certifications", "terms_url", "dpa_url"];
  const rows = items.map((it) =>
    [it.id, it.name, it.role, it.region, it.certifications.join("|"), it.terms_url, it.dpa_url]
      .map((v) => `"${String(v).replace(/"/g, '""')}"`)
      .join(",")
  );
  return [header.join(","), ...rows].join("\n");
}

export function SubProcessorsPage({ locale, version, items }: SubProcessorsPageProps) {
  const headers = HEADERS[locale];

  function handleDownload() {
    const csv = toCsv(items);
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `sub-processors-${version}.csv`;
    a.rel = "noopener";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  return (
    <PublicShell width="wide">
      <PublicPageHeader
        title={TITLE[locale]}
        description={`v${version}`}
        actions={
          <Button variant="ghost" onClick={handleDownload}>
            {headers.download}
          </Button>
        }
      />
      <div className="lin-card lin-card--pad">
        <SubProcessorsTable
          locale={locale}
          caption={TITLE[locale]}
          headers={headers}
          items={items}
        />
      </div>
    </PublicShell>
  );
}

export { toCsv };

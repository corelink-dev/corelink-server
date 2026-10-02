import { SubProcessorsPage } from "./SubProcessorsPage";
import { loadSubProcessors } from "@/content/load";
import type { Locale } from "@/i18n/LocaleContext";

interface RouteParams {
  params: Promise<{ locale: Locale }>;
}

export default async function Page({ params }: RouteParams) {
  const { locale } = await params;
  // The bundled, reviewed list is the only source. This page used to try
  // `/v1/subprocessors` first, but no handler for that path exists anywhere,
  // and a list served from elsewhere could silently disagree with the other
  // published sub-processor surfaces that B-316's verifier keeps identical
  // (scripts/verify_b316_pending_vendor_reviews.py pins this data path).
  const list = loadSubProcessors();
  return <SubProcessorsPage locale={locale} version={list.version} items={list.items} />;
}

import Link from "next/link";
import { ArrowLeft } from "lucide-react";
import { EmptyState, PageHeader } from "@/components/ui";

/** Unknown page, or a record (change request, endpoint …) that does not exist or belongs to another bank. */
export default function NotFound() {
  return (
    <div>
      <PageHeader title="Not found" />
      <EmptyState title="This page or record does not exist">
        It may have been removed, the link may be incomplete, or it belongs to a bank you are not acting for.
      </EmptyState>
      <Link href="/" className="mt-4 inline-flex items-center gap-1.5 text-sm text-muted hover:text-primary">
        <ArrowLeft size={15} aria-hidden /> Back to the dashboard
      </Link>
    </div>
  );
}

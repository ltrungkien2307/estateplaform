import type { KycStatus } from "@/types/user";

interface KycStatusBadgeProps {
  status?: KycStatus;
}

const statusStyles: Record<KycStatus, string> = {
  pending: "border-slate-200/60 bg-slate-100/70 text-slate-700 shadow-sm backdrop-blur-md",
  submitted: "border-indigo-200/60 bg-indigo-100/70 text-indigo-700 shadow-sm backdrop-blur-md",
  reviewing: "border-amber-200/60 bg-amber-100/70 text-amber-700 shadow-sm backdrop-blur-md",
  verified: "border-emerald-200/60 bg-emerald-100/70 text-emerald-700 shadow-sm backdrop-blur-md",
  rejected: "border-rose-200/60 bg-rose-100/70 text-rose-700 shadow-sm backdrop-blur-md",
};

export default function KycStatusBadge({ status = "pending" }: KycStatusBadgeProps) {
  return (
    <span
      className={`inline-flex rounded-full border px-3 py-1 text-xs font-semibold uppercase tracking-wide ${statusStyles[status]}`}
    >
      {status}
    </span>
  );
}


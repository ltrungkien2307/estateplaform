import React from "react";

interface StatCardProps {
  icon: React.ReactNode;
  title: string;
  value: string | number;
  description?: string;
  trend?: "up" | "down" | "stable";
}

export default function StatCard({ icon, title, value, description, trend }: StatCardProps) {
  return (
    <div className="glass-panel relative overflow-hidden p-6 before:absolute before:inset-y-0 before:left-0 before:w-1.5 before:bg-indigo-400" style={{ backgroundColor: "rgba(255, 255, 255, 0.65)", borderColor: "rgba(255, 255, 255, 0.6)" }}>
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <div className="mb-2 flex items-center gap-2">
            <span className="text-2xl text-indigo-800">{icon}</span>
            <h3 className="text-sm font-medium text-slate-600">{title}</h3>
          </div>
          <p className="text-2xl font-bold text-slate-900">{value}</p>
          {description && <p className="mt-2 text-xs text-slate-600">{description}</p>}
        </div>
        {trend && (
          <div
            className={`text-2xl ${
              trend === "up" ? "text-emerald-500" : trend === "down" ? "text-rose-500" : "text-slate-400"
            }`}
          >
            {trend === "up" && "↑"}
            {trend === "down" && "↓"}
            {trend === "stable" && "→"}
          </div>
        )}
      </div>
    </div>
  );
}

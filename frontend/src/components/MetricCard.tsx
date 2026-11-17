import React from "react";
import { LucideIcon } from "lucide-react";

interface MetricCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: LucideIcon;
  variant?: "blue" | "green" | "orange" | "red" | "purple";
  badgeText?: string;
}

export const MetricCard: React.FC<MetricCardProps> = ({
  title,
  value,
  subtitle,
  icon: Icon,
  variant = "blue",
  badgeText,
}) => {
  const variantStyles = {
    blue: {
      iconBg: "bg-[rgba(0,122,255,0.08)]",
      iconColor: "text-[#007AFF]",
      badgeBg: "bg-[rgba(0,122,255,0.08)] text-[#007AFF]",
    },
    green: {
      iconBg: "bg-[rgba(52,199,89,0.1)]",
      iconColor: "text-[#34C759]",
      badgeBg: "bg-[rgba(52,199,89,0.1)] text-[#34C759]",
    },
    orange: {
      iconBg: "bg-[rgba(255,149,0,0.1)]",
      iconColor: "text-[#FF9500]",
      badgeBg: "bg-[rgba(255,149,0,0.1)] text-[#FF9500]",
    },
    red: {
      iconBg: "bg-[rgba(255,59,48,0.08)]",
      iconColor: "text-[#FF3B30]",
      badgeBg: "bg-[rgba(255,59,48,0.08)] text-[#FF3B30]",
    },
    purple: {
      iconBg: "bg-[rgba(175,82,222,0.1)]",
      iconColor: "text-[#AF52DE]",
      badgeBg: "bg-[rgba(175,82,222,0.1)] text-[#AF52DE]",
    },
  };

  const style = variantStyles[variant];

  return (
    <div className="bg-[#FFFFFF] border border-[#E5E5EA] rounded-[18px] p-5 shadow-[0_1px_3px_0_rgba(0,0,0,0.02),0_4px_12px_0_rgba(0,0,0,0.02)] hover:shadow-[0_4px_16px_0_rgba(0,0,0,0.04)] hover:border-[#D1D1D6] transition-all duration-200">
      <div className="flex items-center justify-between mb-3">
        <span className="text-[12px] font-medium text-[#86868B] uppercase tracking-wider">
          {title}
        </span>
        <div className={`w-8 h-8 rounded-xl ${style.iconBg} flex items-center justify-center ${style.iconColor}`}>
          <Icon className="w-4 h-4 stroke-[2.2]" />
        </div>
      </div>

      <div className="flex items-baseline gap-2">
        <span className="text-[28px] font-semibold text-[#1D1D1F] tracking-tight">
          {value}
        </span>
        {badgeText && (
          <span className={`text-[11px] font-semibold px-2 py-0.5 rounded-full ${style.badgeBg}`}>
            {badgeText}
          </span>
        )}
      </div>

      {subtitle && (
        <p className="text-[12px] text-[#86868B] mt-1 font-normal">
          {subtitle}
        </p>
      )}
    </div>
  );
};

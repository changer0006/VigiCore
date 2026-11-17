import React from 'react';

interface VigiCoreLogoProps {
  variant?: 'full' | 'mark';
  size?: 'sm' | 'md' | 'lg' | number;
  theme?: 'light' | 'dark';
  className?: string;
  showSubtitle?: boolean;
}

export const VigiCoreLogo: React.FC<VigiCoreLogoProps> = ({
  variant = 'full',
  size = 'md',
  theme = 'light',
  className = '',
  showSubtitle = true,
}) => {
  // Dimension calculations
  let markSize = 36;
  if (typeof size === 'number') {
    markSize = size;
  } else if (size === 'sm') {
    markSize = 28;
  } else if (size === 'lg') {
    markSize = 44;
  }

  const markSvg = (
    <svg
      width={markSize}
      height={markSize}
      viewBox="0 0 48 48"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className="flex-shrink-0 transition-transform duration-200 group-hover:scale-105"
      aria-hidden="true"
    >
      <defs>
        <linearGradient id="vgGradComponent" x1="6" y1="4" x2="42" y2="44" gradientUnits="userSpaceOnUse">
          <stop stopColor="#007AFF" />
          <stop offset="1" stopColor="#0051C7" />
        </linearGradient>
        <linearGradient id="vgLensRingComponent" x1="14" y1="12" x2="34" y2="32" gradientUnits="userSpaceOnUse">
          <stop stopColor="#FFFFFF" stopOpacity="0.95" />
          <stop offset="1" stopColor="#DCEBFF" />
        </linearGradient>
        <filter id="vgShadowComponent" x="2" y="2" width="44" height="46" filterUnits="userSpaceOnUse" colorInterpolationFilters="sRGB">
          <feDropShadow dx="0" dy="2" stdDeviation="2.5" floodColor="#0051C7" floodOpacity="0.25" />
        </filter>
      </defs>

      {/* Security Shield Outer Geometry */}
      <g filter="url(#vgShadowComponent)">
        <path
          d="M24 3.5C33.5 3.5 42 7.5 42 16.5C42 29.5 31.5 39.5 24 44.5C16.5 39.5 6 29.5 6 16.5C6 7.5 14.5 3.5 24 3.5Z"
          fill="url(#vgGradComponent)"
        />
      </g>

      {/* Inner Shield Subtle Accent Line */}
      <path
        d="M24 6.5C32 6.5 39 10 39 17.5C39 28.5 30 37.5 24 41.5C18 37.5 9 28.5 9 17.5C9 10 16 6.5 24 6.5Z"
        stroke="#FFFFFF"
        strokeOpacity="0.2"
        strokeWidth="1.5"
        fill="none"
      />

      {/* CCTV Top Mount Bracket */}
      <rect x="20.5" y="8.5" width="7" height="2.5" rx="1.25" fill="#FFFFFF" fillOpacity="0.9" />
      <rect x="22.5" y="11" width="3" height="2" fill="#FFFFFF" fillOpacity="0.9" />

      {/* CCTV Camera Lens Structure */}
      <circle cx="24" cy="23" r="10" stroke="url(#vgLensRingComponent)" strokeWidth="2.5" fill="#003D9E" fillOpacity="0.4" />
      <circle cx="24" cy="23" r="10" stroke="#FFFFFF" strokeOpacity="0.5" strokeWidth="1.5" strokeDasharray="3 4" fill="none" />
      <circle cx="24" cy="23" r="6" fill="#FFFFFF" />
      <circle cx="24" cy="23" r="3.75" fill="#007AFF" />
      <circle cx="25.5" cy="21.5" r="1.25" fill="#FFFFFF" />
    </svg>
  );

  if (variant === 'mark') {
    return (
      <div className={`inline-flex items-center justify-center ${className}`} title="VigiCore">
        {markSvg}
      </div>
    );
  }

  return (
    <div className={`inline-flex items-center gap-3 ${className}`}>
      {markSvg}
      <div className="flex flex-col leading-tight select-none">
        <div className="flex items-baseline tracking-tight">
          <span className={`text-[19px] font-bold ${theme === 'dark' ? 'text-white' : 'text-[#1D1D1F]'}`}>
            Vigi
          </span>
          <span className="text-[19px] font-bold text-[#007AFF]">
            Core
          </span>
        </div>
        {showSubtitle && (
          <span className="text-[9.5px] font-semibold text-[#86868B] tracking-[0.14em] uppercase -mt-0.5">
            CCTV SECURITY PLATFORM
          </span>
        )}
      </div>
    </div>
  );
};

/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        apple: {
          bg: "#F5F5F7",
          card: "#FFFFFF",
          text: "#1D1D1F",
          secondary: "#86868B",
          border: "#E5E5EA",
          blue: "#007AFF",
          blueHover: "#0062CC",
          blueLight: "rgba(0, 122, 255, 0.08)",
          red: "#FF3B30",
          redLight: "rgba(255, 59, 48, 0.08)",
          orange: "#FF9500",
          orangeLight: "rgba(255, 149, 0, 0.08)",
          amber: "#FFCC00",
          amberLight: "rgba(255, 204, 0, 0.12)",
          green: "#34C759",
          greenLight: "rgba(52, 199, 89, 0.1)",
          gray: "#8E8E93",
          grayLight: "rgba(142, 142, 147, 0.1)",
        }
      },
      fontFamily: {
        sans: [
          "-apple-system",
          "BlinkMacSystemFont",
          '"SF Pro Display"',
          '"SF Pro Text"',
          '"Helvetica Neue"',
          "Helvetica",
          "Arial",
          "sans-serif"
        ]
      },
      borderRadius: {
        'apple': '16px',
        'apple-lg': '20px',
        'apple-sm': '12px'
      },
      boxShadow: {
        'apple-subtle': '0 1px 3px 0 rgba(0, 0, 0, 0.03), 0 4px 12px 0 rgba(0, 0, 0, 0.02)',
        'apple-card': '0 2px 8px 0 rgba(0, 0, 0, 0.04), 0 1px 2px 0 rgba(0, 0, 0, 0.02)',
        'apple-hover': '0 6px 16px 0 rgba(0, 0, 0, 0.06), 0 2px 4px 0 rgba(0, 0, 0, 0.02)',
      }
    },
  },
  plugins: [],
}

/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        wavs: {
          bg: "#f6f7f3",
          elevated: "#eef2ea",
          panel: "rgba(255, 255, 255, 0.9)",
          soft: "#f8faf7",
          border: "#d8e0d4",
          "border-strong": "#bfcabc",
          text: "#17201a",
          softtext: "#334137",
          muted: "#667569",
          accent: "#146c43",
          "accent-strong": "#0f5635",
        },
        risk: {
          high: "#b33b3b",
          medium: "#9a6510",
          low: "#1b7a53",
          info: "#486454",
        },
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "monospace"],
      },
      boxShadow: {
        wavs: "0 18px 46px rgba(52, 69, 58, 0.08)",
        topbar: "0 10px 26px rgba(52, 69, 58, 0.05)",
      },
    },
  },
  plugins: [],
};

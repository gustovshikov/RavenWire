module.exports = {
  content: [
    "../lib/**/*.{ex,heex}",
    "../config/**/*.exs"
  ],
  theme: {
    extend: {
      colors: {
        orbital: {
          void: "#0B0E14",
          slate: "#171A21",
          highlight: "#242933",
          border: "#2D323B",
          text: "#E2E8F0",
          muted: "#8B949E",
          cyan: "#1793D1",
          crimson: "#F43F5E",
          green: "#10B981",
          amber: "#F59E0B"
        }
      },
      fontFamily: {
        mono: ["JetBrains Mono", "Fira Code", "ui-monospace", "SFMono-Regular", "Menlo", "Consolas", "monospace"]
      },
      boxShadow: {
        plasma: "0 0 0 1px rgba(45, 50, 59, 0.75), 0 18px 42px rgba(0, 0, 0, 0.22)",
        "cyan-glow": "0 0 22px rgba(23, 147, 209, 0.22)",
        "crimson-glow": "0 0 22px rgba(244, 63, 94, 0.20)"
      }
    }
  },
  plugins: []
};

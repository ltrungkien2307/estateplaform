import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./contexts/**/*.{js,ts,jsx,tsx,mdx}",
    "./services/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ["Manrope", "Inter", "ui-sans-serif", "system-ui", "sans-serif"],
      },
      colors: {
        brand: {
          50: "#eef2ff",
          100: "#e0e7ff",
          500: "#6366f1",
          700: "#4338ca",
        },
        primary: {
          light: "var(--color-primary-light)",
          dark: "var(--color-primary-dark)",
        },
        secondary: "var(--color-secondary)",
        accent: "var(--color-accent)",
        background: {
          light: "var(--color-background-light)",
        },
        surface: "var(--color-surface)",
        text: {
          primary: "var(--color-text-primary)",
          secondary: "var(--color-text-secondary)",
        },
      },
      boxShadow: {
        glass: "0 16px 45px -24px rgba(15, 23, 42, 0.35)",
        sm: "var(--shadow-sm)",
        md: "var(--shadow-md)",
        lg: "var(--shadow-lg)",
      },
      spacing: {
        xs: "var(--spacing-xs)",
        sm: "var(--spacing-sm)",
        md: "var(--spacing-md)",
        lg: "var(--spacing-lg)",
        xl: "var(--spacing-xl)",
      },
      borderRadius: {
        sm: "var(--border-radius-sm)",
        md: "var(--border-radius-md)",
        lg: "var(--border-radius-lg)",
      },
      transitionDuration: {
        fast: "var(--transition-duration-fast)",
        normal: "var(--transition-duration-normal)",
      },
      transitionTimingFunction: {
        DEFAULT: "var(--transition-easing)",
      },
      animation: {
        "rise-up": "rise-up var(--transition-duration-normal) var(--transition-easing)",
        "slide-down": "slide-down var(--transition-duration-normal) var(--transition-easing)",
        "fade-in": "fade-in var(--transition-duration-normal) var(--transition-easing)",
        "scale-in": "scale-in var(--transition-duration-normal) var(--transition-easing)",
      },
      keyframes: {
        "rise-up": {
          "0%": { opacity: "0", transform: "translateY(8px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
        "slide-down": {
          "0%": { opacity: "0", transform: "translateY(-8px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
        "fade-in": {
          "0%": { opacity: "0" },
          "100%": { opacity: "1" },
        },
        "scale-in": {
          "0%": { opacity: "0", transform: "scale(0.95)" },
          "100%": { opacity: "1", transform: "scale(1)" },
        },
      },
    },
  },
  plugins: [],
};

export default config;


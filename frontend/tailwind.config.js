module.exports = {
    darkMode: ["class"],
    content: [
        "./src/**/*.{js,jsx,ts,tsx}",
        "./public/index.html",
    ],
    theme: {
        extend: {
            fontFamily: {
                sans: ['"IBM Plex Sans"', 'system-ui', 'sans-serif'],
                mono: ['"JetBrains Mono"', 'monospace'],
            },
            colors: {
                border: "hsl(var(--border))",
                input: "hsl(var(--input))",
                ring: "hsl(var(--ring))",
                background: "hsl(var(--background))",
                foreground: "hsl(var(--foreground))",
                primary: {
                    DEFAULT: "hsl(var(--primary))",
                    foreground: "hsl(var(--primary-foreground))",
                },
                secondary: {
                    DEFAULT: "hsl(var(--secondary))",
                    foreground: "hsl(var(--secondary-foreground))",
                },
                destructive: {
                    DEFAULT: "hsl(var(--destructive))",
                    foreground: "hsl(var(--destructive-foreground))",
                },
                muted: {
                    DEFAULT: "hsl(var(--muted))",
                    foreground: "hsl(var(--muted-foreground))",
                },
                accent: {
                    DEFAULT: "hsl(var(--accent))",
                    foreground: "hsl(var(--accent-foreground))",
                },
                popover: {
                    DEFAULT: "hsl(var(--popover))",
                    foreground: "hsl(var(--popover-foreground))",
                },
                card: {
                    DEFAULT: "hsl(var(--card))",
                    foreground: "hsl(var(--card-foreground))",
                },
                cyan: {
                    DEFAULT: "#06b6d4",
                    hover: "#0891b2",
                },
                risk: {
                    low: "#22c55e",
                    medium: "#eab308",
                    high: "#f97316",
                    critical: "#ef4444",
                },
            },
            borderRadius: {
                lg: "var(--radius)",
                md: "calc(var(--radius) - 2px)",
                sm: "calc(var(--radius) - 4px)",
            },
            keyframes: {
                "pulse-cyan": {
                    "0%, 100%": { opacity: 1 },
                    "50%": { opacity: 0.4 },
                },
                blink: {
                    "0%, 50%": { opacity: 1 },
                    "51%, 100%": { opacity: 0 },
                },
            },
            animation: {
                "pulse-cyan": "pulse-cyan 1.5s ease-in-out infinite",
                blink: "blink 1s steps(1) infinite",
            },
        },
    },
    plugins: [require("tailwindcss-animate")],
};

import "./globals.css";

export const metadata = {
  title: "ThreatLens",
  description: "Security event monitoring and alert triage",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
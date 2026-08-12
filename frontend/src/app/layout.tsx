import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-inter",
  display: "swap",
});

export const metadata: Metadata = {
  title: "SentinelGraph — AI Security Assessment Platform",
  description:
    "AI-powered autonomous web application security assessment platform. Discover, analyze, and verify vulnerabilities with intelligent automation.",
  keywords: ["security", "vulnerability", "scanner", "AI", "web application", "pentesting"],
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className={inter.variable}>
      <body>
        {children}
      </body>
    </html>
  );
}


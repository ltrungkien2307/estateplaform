import "@/styles/globals.css";
import type { AppProps } from "next/app";
import Head from "next/head";
import { AuthProvider } from "@/contexts/AuthContext";

export default function App({ Component, pageProps }: AppProps) {
  return (
    <AuthProvider>
      <Head>
        <title>EstateManager</title>
        <meta
          name="description"
          content="EstateManager modern frontend foundation with authentication flow."
        />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
      </Head>
      <Component {...pageProps} />
    </AuthProvider>
  );
}

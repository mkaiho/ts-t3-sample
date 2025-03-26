import { PrismaAdapter } from "@auth/prisma-adapter";
import { type DefaultSession, type NextAuthConfig } from "next-auth";
import "next-auth/jwt";
import CredentialsProvider from "next-auth/providers/credentials";
import DiscordProvider from "next-auth/providers/discord";
import GithubProver from "next-auth/providers/github";
import GoogleProver from "next-auth/providers/google";
import { z } from "zod";

import { db } from "@/server/db";

/**
 * Module augmentation for `next-auth` types. Allows us to add custom properties to the `session`
 * object and keep type safety.
 *
 * @see https://next-auth.js.org/getting-started/typescript#module-augmentation
 */
declare module "next-auth" {
  interface Session extends DefaultSession {
    user: {
      id: string;
      // ...other properties
      // role: UserRole;
    } & DefaultSession["user"];
    provider: string;
  }

  // interface User {
  //   // ...other properties
  //   // role: UserRole;
  // }
}

declare module "next-auth/jwt" {
  interface DefaultJWT {
    id?: string | null;
    provider?: string;
  }
  interface JWT extends DefaultJWT {
    id: string;
    email: string;
    provider: string;
  }
}

const credentialsInputSchema = z.object({
  email: z.string().email().min(1),
  password: z.string().min(1),
});

type CredentialInput = z.infer<typeof credentialsInputSchema>;

/**
 * Options for NextAuth.js used to configure adapters, providers, callbacks, etc.
 *
 * @see https://next-auth.js.org/configuration/options
 */
export const authConfig = {
  providers: [
    CredentialsProvider({
      authorize: async (credentials) => {
        const parsedCredentials = await credentialsInputSchema.parseAsync({
          email: credentials.email,
          password: credentials.password,
        });
        return {
          email: parsedCredentials.email,
          password: parsedCredentials.password,
        };
      },
      credentials: {
        email: { label: "Email", type: "text" },
        password: { label: "Password", type: "password" },
      },
    }),
    DiscordProvider,
    GithubProver,
    GoogleProver,
    /**
     * ...add more providers here.
     *
     * Most other providers require a bit more work than the Discord provider. For example, the
     * GitHub provider requires you to add the `refresh_token_expires_in` field to the Account
     * model. Refer to the NextAuth.js docs for the provider you want to use. Example:
     *
     * @see https://next-auth.js.org/providers/github
     */
  ],
  session: {
    strategy: "jwt",
  },
  debug: true,
  adapter: PrismaAdapter(db),
  callbacks: {
    jwt: ({ token, user, account }) => {
      if (user?.id && user?.email) {
        token.id = user.id;
        token.email = user.email;
      }
      if (account?.provider) {
        token.provider = account.provider;
      }
      return { ...token };
    },
    session: ({ session, user, token }) => {
      return {
        ...session,
        user: {
          ...user,
          id: user?.id || token.id,
          email: user?.email || token.email,
        },
        provider: token.provider,
      };
    },
  },
} satisfies NextAuthConfig;

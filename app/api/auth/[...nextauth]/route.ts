import bcrypt from "bcrypt";
import NextAuth, { AuthOptions } from "next-auth";
import GitHubProvider from "next-auth/providers/github";
import GoogleProvider from "next-auth/providers/google";
import CredentialsProvider from "next-auth/providers/credentials";
import { PrismaAdapter } from "@next-auth/prisma-adapter";
import prisma from "@/app/libs/prismadb";


export const authOptions: AuthOptions = {
  adapter: PrismaAdapter(prisma),
  providers: [
    GitHubProvider({
      clientId: process.env.GITHUB_ID as string,
      clientSecret: process.env.GITHUB_SECRET as string,
    }),
    GoogleProvider({
      clientId: process.env.GOOGLE_CLIENT_ID as string,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET as string,
    }),
    CredentialsProvider({
      name: "credentials",
      credentials: {
        email: { label: "Email", type: "text" },
        password: { label: "Password", type: "password" },
      },
      async authorize(credentials) {
        if (!credentials?.email || !credentials?.password) {
          throw new Error("Invalid Credentials");
        }

        const user = await prisma.user.findUnique({
          where: { email: credentials.email },
        });

        if (!user || !user?.hashedPassword) {
          throw new Error("Invalid credentials");
        }

        const isCorrectPassword = await bcrypt.compare(
          credentials.password,
          user.hashedPassword
        );

        if (!isCorrectPassword) {
          throw new Error("Invalid credentials");
        }

        return user;  // Return the user object if authentication is successful
      },
    }),
  ],
  debug: process.env.NODE_ENV === "development", // Enable detailed debugging in development
  session: {
    strategy: "jwt",  // Use JWT for session management
  },
  secret: process.env.NEXTAUTH_SECRET,  // Secret for encryption
  callbacks: {
    async signIn({ user, account }) {
      if (account?.provider) {
        console.log('OAuth Account:', account.provider);
        console.log('OAuth Account ID:', account.providerAccountId);

        // Link OAuth accounts to existing user
        if (user.email) {
          const existingUser = await prisma.user.findUnique({
            where: { email: user.email },
          });

          // If the user exists, check if the OAuth account is linked
          if (existingUser) {
            const linkedAccount = await prisma.account.findFirst({
              where: {
                provider: account.provider,
                providerAccountId: account.providerAccountId,
              },
            });

            if (!linkedAccount) {
              // Link the OAuth account to the existing user
              await prisma.account.create({
                data: {
                  userId: existingUser.id,
                  type: account.type,
                  provider: account.provider,
                  providerAccountId: account.providerAccountId,
                  access_token: account.access_token,
                  refresh_token: account.refresh_token,
                  expires_at: account.expires_at,
                },
              });
            }
          }
        }
      }

      return true;  // Always return true to allow sign-in
    },

    async session({ session, token }) {
        // Ensure session.user is defined
        session.user = session.user || {};
    
        if (token?.id) {
          session.user.id = token.id;  // Add user ID to session
        }
    
        return session;
      },
    
      async jwt({ token, user }) {
        if (user) {
          token.id = user.id;  // Add user ID to the JWT token
        }
        return token;
      },
  },
};

const handler = NextAuth(authOptions);

export { handler as GET, handler as POST };

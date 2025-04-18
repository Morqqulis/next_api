import { User } from '@prisma/client'

declare module 'next/server' {
  interface NextRequest {
    user?: User
    session?: {
      user: User
    } | null
  }
} 
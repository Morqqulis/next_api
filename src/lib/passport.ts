import { PrismaClient, User } from '@prisma/client'
import bcrypt from 'bcryptjs'
import passport from 'passport'
import { ExtractJwt, Strategy as JwtStrategy } from 'passport-jwt'
import { Strategy as LocalStrategy } from 'passport-local'

const prisma = new PrismaClient()

// Настройка локальной стратегии для аутентификации по email и паролю
passport.use(
  new LocalStrategy(
    {
      usernameField: 'email',
      passwordField: 'password',
    },
    async (email: string, password: string, done: (error: Error | null, user?: User | false, options?: { message: string }) => void) => {
      try {
        const user = await prisma.user.findUnique({
          where: { email },
        })

        if (!user) {
          return done(null, false, { message: 'Пользователь не найден' })
        }

        const isValidPassword = await bcrypt.compare(password, user.password)

        if (!isValidPassword) {
          return done(null, false, { message: 'Неверный пароль' })
        }

        return done(null, user)
      } catch (error) {
        return done(error as Error)
      }
    }
  )
)

// Настройка JWT стратегии для проверки токена
passport.use(
  new JwtStrategy(
    {
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: process.env.JWT_SECRET || 'your-secret-key',
    },
    async (payload: { userId: string }, done: (error: Error | null, user?: User | false) => void) => {
      try {
        const user = await prisma.user.findUnique({
          where: { id: payload.userId },
        })

        if (!user) {
          return done(null, false)
        }

        return done(null, user)
      } catch (error) {
        return done(error as Error)
      }
    }
  )
)

export default passport 
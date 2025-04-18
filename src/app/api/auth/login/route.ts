import { PrismaClient } from '@prisma/client'
import bcrypt from 'bcryptjs'
import { SignJWT } from 'jose'
import { NextRequest, NextResponse } from 'next/server'

const prisma = new PrismaClient()

export async function POST(request: NextRequest): Promise<NextResponse> {
	try {
		const body = await request.json()

		// Проверяем наличие обязательных полей
		if (!body.email || !body.password) {
			return NextResponse.json({ error: 'Email и пароль обязательны' }, { status: 400 })
		}

		// Находим пользователя по email
		const user = await prisma.user.findUnique({
			where: { email: body.email },
		})

		if (!user) {
			return NextResponse.json({ error: 'Пользователь не найден' }, { status: 401 })
		}

		// Проверяем пароль
		const isValidPassword = await bcrypt.compare(body.password, user.password)

		if (!isValidPassword) {
			return NextResponse.json({ error: 'Неверный пароль' }, { status: 401 })
		}

		// Генерируем JWT токен с помощью jose
		const secret = new TextEncoder().encode(process.env.JWT_SECRET!)
		const token = await new SignJWT({ userId: user.id })
			.setProtectedHeader({ alg: 'HS256' })
			.setExpirationTime('24h')
			.sign(secret)

		// Возвращаем пользователя без пароля и токен
		// eslint-disable-next-line @typescript-eslint/no-unused-vars
		const { password, ...userWithoutPassword } = user

		return NextResponse.json({
			user: userWithoutPassword,
			token,
		})
	} catch (error) {
		console.error('Login error:', error)
		return NextResponse.json({ error: 'Ошибка аутентификации' }, { status: 500 })
	}
}

import { userSchema } from '@/app/api/users/types'
import { userService } from '@/app/api/users/user-service'
import { SignJWT } from 'jose'
import { NextRequest, NextResponse } from 'next/server'
import { ZodError } from 'zod'

export async function POST(request: NextRequest): Promise<NextResponse> {
	try {
		const body = await request.json()

		// Проверяем наличие обязательных полей
		if (!body.email || !body.password || !body.name) {
			return NextResponse.json({ error: 'Email, пароль и имя обязательны' }, { status: 400 })
		}

		const validatedData = userSchema.parse(body)
		const user = await userService.createUser(validatedData)

		// Генерируем JWT токен для нового пользователя с помощью jose
		const secret = new TextEncoder().encode(process.env.JWT_SECRET!)
		const token = await new SignJWT({ userId: user.id })
			.setProtectedHeader({ alg: 'HS256' })
			.setExpirationTime('24h')
			.sign(secret)

		// Возвращаем пользователя без пароля и токен
		// eslint-disable-next-line @typescript-eslint/no-unused-vars
		const { password, ...userWithoutPassword } = user

		return NextResponse.json(
			{
				user: userWithoutPassword,
				token,
			},
			{ status: 201 },
		)
	} catch (error) {
		console.error('Register error:', error)

		// Обработка ошибок валидации Zod
		if (error instanceof ZodError) {
			const errors = error.errors.map((err) => ({
				field: err.path.join('.'),
				message: err.message,
			}))
			return NextResponse.json({ errors }, { status: 400 })
		}

		// Обработка ошибки дублирования email
		if (error instanceof Error && error.message === 'Пользователь с таким email уже существует') {
			return NextResponse.json({ error: error.message }, { status: 409 })
		}

		// Обработка других ошибок
		if (error instanceof Error) {
			return NextResponse.json({ error: error.message }, { status: 400 })
		}

		return NextResponse.json({ error: 'Ошибка при регистрации' }, { status: 500 })
	}
}

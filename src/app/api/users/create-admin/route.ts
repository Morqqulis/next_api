import { userSchema } from '@/app/api/users/types'
import { userService } from '@/app/api/users/user-service'
import { UserRole } from '@prisma/client'
import { NextRequest, NextResponse } from 'next/server'
import { ZodError } from 'zod'
import { verifyAuth } from '../../auth/verify-auth'

export async function POST(request: NextRequest): Promise<NextResponse> {
	try {
		// Проверяем авторизацию и права администратора
		const authResult = await verifyAuth(request)
		if (!authResult.success || !authResult.userId) {
			return NextResponse.json({ error: 'Не авторизован' }, { status: 401 })
		}

		// Получаем пользователя из токена
		const user = await userService.getUserById(authResult.userId)
		if (!user || user.role !== UserRole.ADMIN) {
			return NextResponse.json({ error: 'Недостаточно прав' }, { status: 403 })
		}

		const body = await request.json()

		// Проверяем наличие обязательных полей
		if (!body.email || !body.password || !body.name) {
			return NextResponse.json({ error: 'Email, пароль и имя обязательны' }, { status: 400 })
		}

		// Устанавливаем роль ADMIN
		const adminData = {
			...body,
			role: UserRole.ADMIN,
		}

		const validatedData = userSchema.parse(adminData)
		const newAdmin = await userService.createUser(validatedData)

		// Возвращаем пользователя без пароля
		// eslint-disable-next-line @typescript-eslint/no-unused-vars
		const { password, ...adminWithoutPassword } = newAdmin

		return NextResponse.json(
			{
				user: adminWithoutPassword,
			},
			{ status: 201 },
		)
	} catch (error) {
		console.error('Create admin error:', error)

		// Обработка ошибок валидации Zod
		if (error instanceof ZodError) {
			const errors = error.errors.map(err => ({
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

		return NextResponse.json({ error: 'Ошибка при создании администратора' }, { status: 500 })
	}
}

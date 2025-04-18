import { verifyAuth } from '@/app/api/auth/verify-auth'
import { userService } from '@/app/api/users/user-service'
import { NextRequest, NextResponse } from 'next/server'

export async function GET(request: NextRequest): Promise<NextResponse> {
	try {
		// Проверяем авторизацию
		const authResult = await verifyAuth(request)
		if (!authResult.success || !authResult.userId) {
			return NextResponse.json({ error: 'Не авторизован' }, { status: 401 })
		}

		// Получаем информацию о текущем пользователе
		const user = await userService.getUserById(authResult.userId)
		if (!user) {
			return NextResponse.json({ error: 'Пользователь не найден' }, { status: 404 })
		}

		// Возвращаем пользователя без пароля
		// eslint-disable-next-line @typescript-eslint/no-unused-vars
		const { password, ...userWithoutPassword } = user

		return NextResponse.json({ user: userWithoutPassword }, { status: 200 })
	} catch (error) {
		console.error('Get current user error:', error)

		if (error instanceof Error) {
			return NextResponse.json({ error: error.message }, { status: 400 })
		}

		return NextResponse.json({ error: 'Ошибка при получении информации о пользователе' }, { status: 500 })
	}
} 
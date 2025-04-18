import { verifyAuth } from '@/app/api/auth/verify-auth'
import { userService } from '@/app/api/users/user-service'
import { UserRole } from '@prisma/client'
import { NextRequest, NextResponse } from 'next/server'

export async function DELETE(request: NextRequest): Promise<NextResponse> {
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

		// Удаляем всех пользователей, кроме администраторов
		const result = await userService.deleteAllNonAdminUsers()

		return NextResponse.json(
			{
				message: `Удалено ${result.count} пользователей`,
				count: result.count,
			},
			{ status: 200 },
		)
	} catch (error) {
		console.error('Delete all non-admin users error:', error)

		if (error instanceof Error) {
			return NextResponse.json({ error: error.message }, { status: 400 })
		}

		return NextResponse.json({ error: 'Ошибка при удалении пользователей' }, { status: 500 })
	}
} 
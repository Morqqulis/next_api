import { verifyAuth } from '@/app/api/auth/verify-auth'
import { updateUserSchema } from '@/app/api/users/types'
import { userService } from '@/app/api/users/user-service'
import { UserRole } from '@prisma/client'
import { NextRequest, NextResponse } from 'next/server'
import { ZodError } from 'zod'

export async function GET(request: NextRequest, { params }: { params: { id: string } }): Promise<NextResponse> {
	try {
		// Проверяем авторизацию
		const authResult = await verifyAuth(request)
		if (!authResult.success || !authResult.userId) {
			return NextResponse.json({ error: 'Не авторизован' }, { status: 401 })
		}

		// Получаем текущего пользователя
		const currentUser = await userService.getUserById(authResult.userId)
		if (!currentUser) {
			return NextResponse.json({ error: 'Пользователь не найден' }, { status: 404 })
		}

		// Проверяем, является ли пользователь администратором
		const isAdmin = currentUser.role === UserRole.ADMIN

		// Если пользователь не админ и пытается получить данные другого пользователя
		if (!isAdmin && params.id !== authResult.userId) {
			return NextResponse.json({ error: 'У вас нет прав для просмотра данных другого пользователя' }, { status: 403 })
		}

		// Получаем пользователя по ID
		const { id } = await params
		const user = await userService.getUserById(id)
		if (!user) {
			return NextResponse.json({ error: 'Пользователь не найден' }, { status: 404 })
		}

		// Возвращаем пользователя без пароля
		// eslint-disable-next-line @typescript-eslint/no-unused-vars
		const { password, ...userWithoutPassword } = user

		return NextResponse.json({ user: userWithoutPassword }, { status: 200 })
	} catch (error) {
		console.error('Get user error:', error)

		if (error instanceof Error) {
			return NextResponse.json({ error: error.message }, { status: 400 })
		}

		return NextResponse.json({ error: 'Ошибка при получении информации о пользователе' }, { status: 500 })
	}
}

export async function PATCH(request: NextRequest, { params }: { params: { id: string } }): Promise<NextResponse> {
	try {
		const authResult = await verifyAuth(request)
		if (!authResult.success || !authResult.userId) {
			return NextResponse.json({ error: 'Не авторизован' }, { status: 401 })
		}

		// Получаем текущего пользователя
		const currentUser = await userService.getUserById(authResult.userId)
		if (!currentUser) {
			return NextResponse.json({ error: 'Пользователь не найден' }, { status: 404 })
		}

		// Проверяем, является ли пользователь администратором
		const isAdmin = currentUser.role === UserRole.ADMIN

		const body = await request.json()
		const validatedData = updateUserSchema.parse(body)

		// Обновляем пользователя с учетом прав доступа
		const { id } = await params
		const updatedUser = await userService.updateUser(id, validatedData, authResult.userId, isAdmin)

		// Возвращаем пользователя без пароля
		// eslint-disable-next-line @typescript-eslint/no-unused-vars
		const { password, ...userWithoutPassword } = updatedUser

		return NextResponse.json({ user: userWithoutPassword }, { status: 200 })
	} catch (error) {
		console.error('Update user error:', error)

		// Обработка ошибок валидации Zod
		if (error instanceof ZodError) {
			const errors = error.errors.map(err => ({
				field: err.path.join('.'),
				message: err.message,
			}))
			return NextResponse.json({ errors }, { status: 400 })
		}

		// Обработка ошибки доступа
		if (error instanceof Error && error.message.includes('нет прав')) {
			return NextResponse.json({ error: error.message }, { status: 403 })
		}

		// Обработка других ошибок
		if (error instanceof Error) {
			return NextResponse.json({ error: error.message }, { status: 400 })
		}

		return NextResponse.json({ error: 'Ошибка при обновлении пользователя' }, { status: 500 })
	}
}

export async function DELETE(request: NextRequest, { params }: { params: { id: string } }): Promise<NextResponse> {
	try {
		// Проверяем авторизацию
		const authResult = await verifyAuth(request)
		if (!authResult.success || !authResult.userId) {
			return NextResponse.json({ error: 'Не авторизован' }, { status: 401 })
		}

		// Получаем текущего пользователя
		const currentUser = await userService.getUserById(authResult.userId)
		if (!currentUser) {
			return NextResponse.json({ error: 'Пользователь не найден' }, { status: 404 })
		}

		// Проверяем, является ли пользователь администратором
		const isAdmin = currentUser.role === UserRole.ADMIN

		// Удаляем пользователя с учетом прав доступа
		const { id } = await params
		await userService.deleteUser(id, authResult.userId, isAdmin)

		return NextResponse.json({ message: 'Пользователь успешно удален' }, { status: 200 })
	} catch (error) {
		console.error('Delete user error:', error)

		// Обработка ошибки доступа
		if (error instanceof Error && error.message.includes('нет прав')) {
			return NextResponse.json({ error: error.message }, { status: 403 })
		}

		// Обработка других ошибок
		if (error instanceof Error) {
			return NextResponse.json({ error: error.message }, { status: 400 })
		}

		return NextResponse.json({ error: 'Ошибка при удалении пользователя' }, { status: 500 })
	}
}

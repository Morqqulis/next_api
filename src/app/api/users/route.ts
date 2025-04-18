import { verifyAuth } from '@/app/api/auth/verify-auth'
import { UserRole } from '@prisma/client'
import { NextRequest, NextResponse } from 'next/server'
import { updateUserSchema, userSchema } from './types'
import { userService } from './user-service'

export async function GET(request: NextRequest): Promise<NextResponse> {
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
		if (currentUser.role !== UserRole.ADMIN) {
			return NextResponse.json({ error: 'У вас нет прав для просмотра списка пользователей' }, { status: 403 })
		}

		// Получаем список всех пользователей
		const users = await userService.getAllUsers()

		// Возвращаем пользователей без паролей
		const usersWithoutPasswords = users.map(user => {
			// eslint-disable-next-line @typescript-eslint/no-unused-vars
			const { password, ...userWithoutPassword } = user
			return userWithoutPassword
		})

		return NextResponse.json({ users: usersWithoutPasswords }, { status: 200 })
	} catch (error) {
		console.error('Get users error:', error)

		if (error instanceof Error) {
			return NextResponse.json({ error: error.message }, { status: 400 })
		}

		return NextResponse.json({ error: 'Ошибка при получении списка пользователей' }, { status: 500 })
	}
}

export async function POST(request: NextRequest): Promise<NextResponse> {
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
		if (currentUser.role !== UserRole.ADMIN) {
			return NextResponse.json({ error: 'У вас нет прав для создания пользователей' }, { status: 403 })
		}

		const body = await request.json()
		const validatedData = userSchema.parse(body)
		const newUser = await userService.createUser(validatedData)

		// Возвращаем пользователя без пароля
		// eslint-disable-next-line @typescript-eslint/no-unused-vars
		const { password, ...userWithoutPassword } = newUser

		return NextResponse.json({ user: userWithoutPassword }, { status: 201 })
	} catch (error) {
		console.error('Create user error:', error)

		if (error instanceof Error) {
			return NextResponse.json({ error: error.message }, { status: 400 })
		}

		return NextResponse.json({ error: 'Ошибка при создании пользователя' }, { status: 500 })
	}
}

export async function PATCH(request: NextRequest): Promise<NextResponse> {
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

		const body = await request.json()
		const validatedUpdateData = updateUserSchema.parse(body)
		const targetUserId = body.id || authResult.userId

		// Обновляем пользователя с учетом прав доступа
		const updatedUser = await userService.updateUser(
			targetUserId,
			validatedUpdateData,
			authResult.userId,
			isAdmin
		)

		// Возвращаем пользователя без пароля
		// eslint-disable-next-line @typescript-eslint/no-unused-vars
		const { password, ...userWithoutPassword } = updatedUser

		return NextResponse.json({ user: userWithoutPassword }, { status: 200 })
	} catch (error) {
		console.error('Update user error:', error)

		// Обработка ошибки доступа
		if (error instanceof Error && error.message.includes('нет прав')) {
			return NextResponse.json({ error: error.message }, { status: 403 })
		}

		if (error instanceof Error) {
			return NextResponse.json({ error: error.message }, { status: 400 })
		}

		return NextResponse.json({ error: 'Ошибка при обновлении пользователя' }, { status: 500 })
	}
}

export async function DELETE(request: NextRequest): Promise<NextResponse> {
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

		const { searchParams } = new URL(request.url)
		const targetUserId = searchParams.get('id')

		if (!targetUserId) {
			return NextResponse.json({ error: 'ID пользователя не указан' }, { status: 400 })
		}

		// Удаляем пользователя с учетом прав доступа
		await userService.deleteUser(targetUserId, authResult.userId, isAdmin)

		return NextResponse.json({ message: 'Пользователь успешно удален' }, { status: 200 })
	} catch (error) {
		console.error('Delete user error:', error)

		// Обработка ошибки доступа
		if (error instanceof Error && error.message.includes('нет прав')) {
			return NextResponse.json({ error: error.message }, { status: 403 })
		}

		if (error instanceof Error) {
			return NextResponse.json({ error: error.message }, { status: 400 })
		}

		return NextResponse.json({ error: 'Ошибка при удалении пользователя' }, { status: 500 })
	}
} 
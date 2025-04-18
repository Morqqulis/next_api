import { jwtVerify } from 'jose'
import { NextRequest } from 'next/server'

interface AuthResult {
	success: boolean
	userId?: string
	error?: string
}

export async function verifyAuth(request: NextRequest): Promise<AuthResult> {
	try {
		// Получаем токен из заголовка Authorization
		const authHeader = request.headers.get('Authorization')
		if (!authHeader || !authHeader.startsWith('Bearer ')) {
			return { success: false, error: 'Токен не предоставлен' }
		}

		const token = authHeader.split(' ')[1]
		if (!token) {
			return { success: false, error: 'Токен не предоставлен' }
		}

		// Проверяем токен
		const secret = new TextEncoder().encode(process.env.JWT_SECRET!)
		const { payload } = await jwtVerify(token, secret)

		// Проверяем наличие userId в токене
		if (!payload.userId || typeof payload.userId !== 'string') {
			return { success: false, error: 'Недействительный токен' }
		}

		return { success: true, userId: payload.userId }
	} catch (error) {
		console.error('Auth verification error:', error)
		return { success: false, error: 'Ошибка проверки авторизации' }
	}
} 
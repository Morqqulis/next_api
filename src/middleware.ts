import { jwtVerify } from 'jose'
import { NextRequest, NextResponse } from 'next/server'

// Список публичных маршрутов, которые не требуют аутентификации
const PUBLIC_ROUTES = ['/api/auth/login', '/api/auth/register']

// Настройка CORS
// ВНИМАНИЕ: Использование '*' менее безопасно, так как:
// 1. Не позволяет использовать credentials (куки, авторизационные заголовки)
// 2. Позволяет любому домену делать запросы к вашему API
// 3. Может быть небезопасно в production среде
const CORS_CONFIG = {
	// Если true, разрешает запросы с любого origin (менее безопасно)
	allowAllOrigins: process.env.CORS_ALLOW_ALL === 'true',
	// Список разрешенных origins для CORS (используется если allowAllOrigins = false)
	allowedOrigins: process.env.ALLOWED_ORIGINS
		? process.env.ALLOWED_ORIGINS.split(',')
		: ['http://localhost:3000', 'http://localhost:5173'],
	// Список разрешенных методов
	allowedMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
	// Список разрешенных заголовков
	allowedHeaders: [
		'Content-Type',
		'Authorization',
		'X-Requested-With',
		'Accept',
		'Origin',
		'Access-Control-Request-Method',
		'Access-Control-Request-Headers',
	],
	// Максимальное время кэширования preflight запросов (в секундах)
	maxAge: '86400', // 24 часа
}

// Тип для CORS заголовков
type CorsHeaders = {
	'Access-Control-Allow-Origin': string
	'Access-Control-Allow-Methods': string
	'Access-Control-Allow-Headers': string
	'Access-Control-Max-Age': string
	'Access-Control-Allow-Credentials'?: string
}

export async function middleware(request: NextRequest) {
	// Получаем origin из заголовка запроса
	const origin = request.headers.get('origin') || ''

	// Проверяем, является ли origin разрешенным
	const isAllowedOrigin = CORS_CONFIG.allowAllOrigins ? true : CORS_CONFIG.allowedOrigins.includes(origin)

	// Создаем базовые CORS заголовки
	const corsHeaders: CorsHeaders = {
		'Access-Control-Allow-Origin': CORS_CONFIG.allowAllOrigins
			? '*'
			: isAllowedOrigin
			? origin
			: CORS_CONFIG.allowedOrigins[0],
		'Access-Control-Allow-Methods': CORS_CONFIG.allowedMethods.join(', '),
		'Access-Control-Allow-Headers': CORS_CONFIG.allowedHeaders.join(', '),
		'Access-Control-Max-Age': CORS_CONFIG.maxAge,
	}

	// Добавляем Allow-Credentials только если не используется '*'
	if (!CORS_CONFIG.allowAllOrigins) {
		corsHeaders['Access-Control-Allow-Credentials'] = 'true'
	}

	// Обработка preflight запросов
	if (request.method === 'OPTIONS') {
		return NextResponse.json({}, { headers: corsHeaders })
	}

	// Проверяем, является ли маршрут публичным
	const isPublicRoute = PUBLIC_ROUTES.some(route => request.nextUrl.pathname === route)

	// Если маршрут публичный, пропускаем аутентификацию
	if (isPublicRoute) {
		const response = NextResponse.next()
		Object.entries(corsHeaders).forEach(([key, value]) => {
			response.headers.set(key, value)
		})
		return response
	}

	// Проверяем аутентификацию для защищенных маршрутов
	if (request.nextUrl.pathname.startsWith('/api/')) {
		try {
			// Получаем токен из заголовка Authorization
			const authHeader = request.headers.get('Authorization')

			if (!authHeader || !authHeader.startsWith('Bearer ')) {
				return NextResponse.json(
					{ error: 'Не авторизован' },
					{
						status: 401,
						headers: corsHeaders,
					},
				)
			}

			const token = authHeader.split(' ')[1]

			// Проверяем токен
			const secret = new TextEncoder().encode(process.env.JWT_SECRET)
			if (!secret) {
				throw new Error('JWT_SECRET не настроен')
			}

			const { payload } = await jwtVerify(token, secret)

			if (!payload.userId) {
				throw new Error('Токен не содержит userId')
			}

			// Добавляем userId к запросу
			const requestHeaders = new Headers(request.headers)
			requestHeaders.set('x-user-id', payload.userId as string)

			// Создаем ответ с обновленными заголовками
			const response = NextResponse.next({
				request: {
					headers: requestHeaders,
				},
			})

			// Добавляем CORS заголовки
			Object.entries(corsHeaders).forEach(([key, value]) => {
				response.headers.set(key, value)
			})

			return response
		} catch (error) {
			console.error('Auth error:', error)

			// Формируем сообщение об ошибке
			let errorMessage = 'Не авторизован'
			if (error instanceof Error) {
				if (error.message === 'JWT_SECRET не настроен') {
					errorMessage = 'Ошибка конфигурации сервера'
				} else if (error.message.includes('JWT')) {
					errorMessage = 'Недействительный токен'
				}
			}

			return NextResponse.json(
				{ error: errorMessage },
				{
					status: 401,
					headers: corsHeaders,
				},
			)
		}
	}

	// Для всех остальных маршрутов
	const response = NextResponse.next()
	Object.entries(corsHeaders).forEach(([key, value]) => {
		response.headers.set(key, value)
	})
	return response
}

export const config = {
	matcher: ['/api/:path*', '/((?!_next/static|_next/image|favicon.ico).*)'],
}

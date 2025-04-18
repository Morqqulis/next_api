import { cookies } from 'next/headers'
import { NextResponse } from 'next/server'

export async function POST(): Promise<NextResponse> {
	// В JWT аутентификации нет необходимости в серверном логауте
	// Клиент должен удалить токен на своей стороне
	const cookieStore = await cookies()
	cookieStore.delete('token')
	return NextResponse.json({ success: true })
}

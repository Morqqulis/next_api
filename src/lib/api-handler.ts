import { NextRequest, NextResponse } from 'next/server'
import { ZodError } from 'zod'
import { ApiError } from './api-error'

type ApiHandler = (request: NextRequest) => Promise<NextResponse>

export function withErrorHandler(handler: ApiHandler): ApiHandler {
  return async (request: NextRequest) => {
    try {
      return await handler(request)
    } catch (error) {
      console.error('API Error:', error)

      if (error instanceof ApiError) {
        return NextResponse.json(
          {
            error: error.message,
            errors: error.errors,
          },
          { status: error.statusCode }
        )
      }

      if (error instanceof ZodError) {
        return NextResponse.json(
          {
            error: 'Ошибка валидации',
            errors: error.errors.reduce((acc, curr) => {
              const path = curr.path.join('.')
              if (!acc[path]) {
                acc[path] = []
              }
              acc[path].push(curr.message)
              return acc
            }, {} as Record<string, string[]>),
          },
          { status: 400 }
        )
      }

      return NextResponse.json(
        { error: 'Внутренняя ошибка сервера' },
        { status: 500 }
      )
    }
  }
} 
export class ApiError extends Error {
  constructor(
    public statusCode: number,
    message: string,
    public errors?: Record<string, string[]>
  ) {
    super(message)
    this.name = 'ApiError'
  }

  static badRequest(message: string, errors?: Record<string, string[]>) {
    return new ApiError(400, message, errors)
  }

  static unauthorized(message = 'Не авторизован') {
    return new ApiError(401, message)
  }

  static forbidden(message = 'Доступ запрещен') {
    return new ApiError(403, message)
  }

  static notFound(message = 'Ресурс не найден') {
    return new ApiError(404, message)
  }

  static tooManyRequests(message = 'Слишком много запросов') {
    return new ApiError(429, message)
  }

  static internal(message = 'Внутренняя ошибка сервера') {
    return new ApiError(500, message)
  }
} 
import { UserRole } from '@prisma/client'
import { z } from 'zod'

export const userSchema = z.object({
	email: z.string().email('Некорректный email'),
	password: z.string().min(3, 'Пароль должен содержать минимум 3 символов'),
	name: z.string().min(2, 'Имя должно содержать минимум 2 символа'),
	role: z.nativeEnum(UserRole).default(UserRole.USER),
})

export const updateUserSchema = userSchema.partial()

export type UserInput = z.infer<typeof userSchema>
export type UpdateUserInput = z.infer<typeof updateUserSchema>

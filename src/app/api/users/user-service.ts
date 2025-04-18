import { Prisma, PrismaClient, User, UserRole } from '@prisma/client'
import bcrypt from 'bcryptjs'
import { UpdateUserInput, UserInput } from './types'

const prisma = new PrismaClient()

export class UserService {
	async getAllUsers(): Promise<User[]> {
		return prisma.user.findMany()
	}

	async getUserById(id: string): Promise<User | null> {
		return prisma.user.findUnique({
			where: { id },
		})
	}

	async createUser(data: UserInput): Promise<User> {
		try {
			const hashedPassword = await bcrypt.hash(data.password, 10)

			return await prisma.user.create({
				data: {
					...data,
					password: hashedPassword,
				},
			})
		} catch (error) {
			if (error instanceof Prisma.PrismaClientKnownRequestError) {
				if (error.code === 'P2002') {
					const field = error.meta?.target as string[] | undefined
					if (field?.includes('email')) {
						throw new Error('Пользователь с таким email уже существует')
					}
				}
			}
			throw error
		}
	}

	async updateUser(id: string, data: UpdateUserInput, currentUserId: string, isAdmin: boolean): Promise<User> {
		// Проверяем, что пользователь обновляет только свои данные, если он не админ
		if (!isAdmin && id !== currentUserId) {
			throw new Error('У вас нет прав для обновления данных другого пользователя')
		}

		const updateData = { ...data }

		if (data.password) {
			updateData.password = await bcrypt.hash(data.password, 10)
		}

		return prisma.user.update({
			where: { id },
			data: updateData,
		})
	}

	async deleteUser(id: string, currentUserId: string, isAdmin: boolean): Promise<User> {
		// Проверяем, что пользователь удаляет только свои данные, если он не админ
		if (!isAdmin && id !== currentUserId) {
			throw new Error('У вас нет прав для удаления другого пользователя')
		}

		return prisma.user.delete({
			where: { id },
		})
	}

	async deleteAllNonAdminUsers(): Promise<{ count: number }> {
		const result = await prisma.user.deleteMany({
			where: {
				role: {
					not: UserRole.ADMIN
				}
			}
		})

		return { count: result.count }
	}
}

export const userService = new UserService()

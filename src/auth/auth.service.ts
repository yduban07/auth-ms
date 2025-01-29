import { Injectable, OnModuleInit, Logger, HttpStatus } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';
import { PrismaClient } from '@prisma/client';
import { SigninUserDto, SignupUserDto } from './dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { envs } from 'src/config';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
    private readonly logger = new Logger('AuthService');

    constructor(
        private readonly jwtService: JwtService
    ) {
        super();
    }
    async onModuleInit() {
        await this.$connect();
        this.logger.log('Mongodb connected');
    }

    async signJWT(payload: JwtPayload) {
        return this.jwtService.sign(payload);
    }

    async signupUser(signupUserDto: SignupUserDto) {
        const { email, name, password } = signupUserDto;

        try {
            const userDb = await this.user.findUnique({
                where: {
                    email: email
                }
            });

            if (userDb) {
                throw new RpcException({
                    status: 400,
                    message: 'User already exists'
                });
            }

            const user = await this.user.create({
                data: {
                    email: email,
                    name: name,
                    password: bcrypt.hashSync(password, 10),
                }
            });


            const { password: __, ...rest } = user;

            return {
                user: rest,
                token: await this.signJWT(rest)
            };

        } catch (error) {
            throw new RpcException({
                status: HttpStatus.BAD_REQUEST,
                message: error.message
            });
        }
    }

    async signinUser(signinUserDto: SigninUserDto) {
        const { email, password } = signinUserDto;

        try {
            const userDb = await this.user.findUnique({
                where: {
                    email: email
                }
            });

            if (!userDb) {
                throw new RpcException({
                    status: HttpStatus.BAD_REQUEST,
                    message: 'Invalid credentials'
                });
            }

            const isPasswordValid = bcrypt.compareSync(password, userDb.password);

            if (!isPasswordValid) {
                throw new RpcException({
                    status: HttpStatus.BAD_REQUEST,
                    message: 'Invalid credentials'
                });
            }

            const { password: __, ...rest } = userDb;

            return {
                user: rest,
                token: await this.signJWT(rest),
            };

        } catch (error) {
            throw new RpcException({
                status: 400,
                message: error.message
            });
        }
    }

    async verifyToken(token: string) {
        try {

            const { sub, iat, exp, ...user } = this.jwtService.verify(token, {
                secret: envs.jwtSecret,
            });

            return {
                user: user,
                token: await this.signJWT(user),
            }


        } catch (error) {
            throw new RpcException({
                status: HttpStatus.UNAUTHORIZED,
                message: 'Invalid token'
            });
        }
    }

}

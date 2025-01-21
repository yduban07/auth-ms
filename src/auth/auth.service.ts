import { Injectable, OnModuleInit, Logger } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';
import { PrismaClient } from '@prisma/client';
import { SignupUserDto } from './dto';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
    private readonly logger =  new Logger('AuthService');

    async onModuleInit() {
        await this.$connect();
        this.logger.log('Mongodb connected');
    }

    async signupUser(signupUserDto: SignupUserDto ) {
        const {email, name, password} = signupUserDto;

        try {
            const userDb = await this.user.findUnique({
                where: {
                    email: email
                }
            }); 

            if( userDb ) {
                throw new RpcException({
                    status: 400,
                    message: 'Use already exists'
                });
            } 

            const user =  await this.user.create({
                data: {
                    email: email,
                    name: name,
                    password: bcrypt.hashSync(password, 10),
                }
            });
            

            const { password:__, ...rest } =  user;

            return {
                user: rest,
                token: __
            };
            
        } catch (error) {
            throw new RpcException({
                status: 400,
                message: error.message
            });
        }
    }

}

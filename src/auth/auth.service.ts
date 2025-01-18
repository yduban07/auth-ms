import { Injectable, OnModuleInit, Logger } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
    private readonly logger =  new Logger('AuthService');

    async onModuleInit() {
        await this.$connect();
        this.logger.log('Mongodb connected');
    }



}

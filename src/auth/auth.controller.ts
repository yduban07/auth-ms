import { Controller } from '@nestjs/common';
import { AuthService } from './auth.service';
import { MessagePattern, Payload } from '@nestjs/microservices';
import { SigninUserDto, SignupUserDto } from './dto';

@Controller()
export class AuthController {
  constructor(private readonly authService: AuthService) { }

  @MessagePattern('auth.signup.user')
  registerUser(@Payload() signupUserDto: SignupUserDto) {
    return signupUserDto;
  }

  @MessagePattern('auth.signin.user')
  loginUser(@Payload() signinUserDto: SigninUserDto) {
    return signinUserDto;
  }

  @MessagePattern('auth.verify.user')
  verifyToken(@Payload() token: string) {
  }
}

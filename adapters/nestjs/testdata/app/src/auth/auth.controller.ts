import { Controller, Post, Get } from '@nestjs/common';
import { Public } from '../common/public.decorator';

@Controller('auth')
export class AuthController {
  // PUBLIC: explicitly opts out of the global guard.
  @Public()
  @Post('sign-in')
  async signIn(): Promise<void> {}

  // AUTHENTICATED: inherits the global guard, no opt-out.
  @Post('sign-out')
  async signOut(): Promise<void> {}
}

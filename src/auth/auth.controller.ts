import { Controller, Get, UseGuards, Post, Body, Res, HttpStatus } from '@nestjs/common';
import { AuthService } from './auth.service';
import { Response } from 'express';
import { JwtAuthGuard } from './jwt-auth.guard';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signin')
  async signIn(@Body() body: { username: string; password: string }, @Res() response: Response) {
    try {
      const newUser = await this.authService.signIn(body.username, body.password);
      return response.status(HttpStatus.CREATED).json(newUser);
    } catch (error) {
      return response.status(HttpStatus.BAD_REQUEST).json({ message: error.message });
    }
  }

  @Post('login')
  async login(@Body() body: { username: string; password: string }, @Res() response: Response) {
    try {
      // Validate user credentials
      const user = await this.authService.validateUser(body.username, body.password);
      if (!user) {
        return response.status(HttpStatus.UNAUTHORIZED).json({ message: 'Invalid credentials' });
      }

      // Generate tokens
      const tokens = await this.authService.login(user);

      // Set the access token in an HttpOnly cookie
      response.cookie('access_token', tokens.access_token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 15 * 60 * 1000, // 15 minutes
      });

      // Set the refresh token in an HttpOnly cookie
      response.cookie('refresh_token', tokens.refresh_token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      });

      return response.status(HttpStatus.OK).json({ message: 'Login successful' });
    } catch (error) {
      return response.status(HttpStatus.INTERNAL_SERVER_ERROR).json({ message: error.message });
    }
  }

  @Post('refresh')
  async refresh(@Body('refreshToken') refreshToken: string, @Res() response: Response) {
    try {
      const newTokens = await this.authService.refresh(refreshToken);

      // Set the new access token in an HttpOnly cookie
      response.cookie('access_token', newTokens.access_token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 15 * 60 * 1000, // 15 minutes
      });

      return response.status(HttpStatus.OK).json({ message: 'Token refreshed' });
    } catch (error) {
      return response.status(HttpStatus.UNAUTHORIZED).json({ message: error.message });
    }
  }

  @Get('protected')
  @UseGuards(JwtAuthGuard)
  getProtectedResource() {
    return { message: 'You have access to this protected resource!' };
  }
}

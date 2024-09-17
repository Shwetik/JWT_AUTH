import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../../prisma/prisma.service';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly prisma: PrismaService
  ) {}

  // Sign-in method for registering a new user
  async signIn(username: string, password: string): Promise<any> {
    // Check if user already exists in the database
    const existingUser = await this.prisma.user.findUnique({
      where: { username },
    });

    if (existingUser) {
      throw new Error('User already exists');
    }

    // Hash the password before saving it to the database
    const hashedPassword = await bcrypt.hash(password, 10);

    // Register new user in the database
    const newUser = await this.prisma.user.create({
      data: {
        username,
        password: hashedPassword,
      },
    });

    return {
      message: 'User registered successfully',
      user: { id: newUser.id, username: newUser.username },
    };
  }

  // Validate user credentials
  async validateUser(username: string, pass: string): Promise<any> {
    // Find the user by username
    const user = await this.prisma.user.findUnique({
      where: { username },
    });

    if (user && (await bcrypt.compare(pass, user.password))) {
      const { password, ...result } = user;
      return result;
    }
    return null;
  }

  // Login method to generate access and refresh tokens
  async login(user: any) {
    const payload = { username: user.username, sub: user.id };
    const accessToken = this.jwtService.sign(payload, { expiresIn: '15m' });
    const refreshToken = this.jwtService.sign(payload, { expiresIn: '7d' });

    return {
      access_token: accessToken,
      refresh_token: refreshToken,
    };
  }

  // Refresh the access token using a valid refresh token
  async refresh(refreshToken: string) {
    try {
      const payload = this.jwtService.verify(refreshToken);
      const newAccessToken = this.jwtService.sign(
        { username: payload.username, sub: payload.sub },
        { expiresIn: '15m' }
      );
      return { access_token: newAccessToken };
    } catch (error) {
      throw new Error('Invalid refresh token');
    }
  }
}

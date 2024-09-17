import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { JwtStrategy } from './jwt.strategy';
import { PrismaService } from '../../prisma/prisma.service'; // Import PrismaService

@Module({
  imports: [
    PassportModule,
    JwtModule.register({
      secret: 'yourSecretKey', // Replace with your actual secret key or use environment variables
      signOptions: { expiresIn: '15m' }, // Token expiration time
    }),
  ],
  providers: [AuthService, JwtStrategy, PrismaService], // Add PrismaService to the providers
  controllers: [AuthController],
  exports: [AuthService], // Export AuthService if needed in other modules
})
export class AuthModule {}

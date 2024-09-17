import { Injectable, CanActivate, ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(private readonly jwtService: JwtService) {}

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest();
    const token = request.cookies['access_token']; // Extract JWT from cookies

    if (!token) {
      throw new UnauthorizedException('No JWT token found in cookies');
    }

    try {
      const payload = this.jwtService.verify(token);
      request.user = payload; // Attach decoded payload to the request object
      return true;
    } catch (err) {
      throw new UnauthorizedException('Invalid or expired token');
    }
  }
}

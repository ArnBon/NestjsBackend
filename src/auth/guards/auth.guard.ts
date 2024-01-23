import { Controller, Get, Post, Body, Patch, Param, Delete, UseGuards, Request } from '@nestjs/common';
import { AuthService } from './../auth.service';
import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Observable } from 'rxjs';
import { JwtPayload } from 'src/auth/interfaces/jwt-payload';

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(
    private jwtService: JwtService,
    private authService: AuthService,    
  ) {}


  async canActivate( context: ExecutionContext ): Promise<boolean>{
    
    const request = context.switchToHttp().getRequest();
    const token = this.extractTokenFromHeader(request);
console.log({token});
    if(!token){
      throw new UnauthorizedException('No hay token en la petición');
    }

    try {
      const payload = await this.jwtService.verifyAsync<JwtPayload>(
          token, {secret: process.env.JWT_SEED}
      );
      const user = await this.authService.findUserById( payload.id );
      if ( !user ) throw new UnauthorizedException('El usuario no existe');
      if ( !user.isActive ) throw new UnauthorizedException('El usuario no esta activo');
// console.log({user});
      request['user'] = user;
      
    } catch (error) {
      throw new UnauthorizedException();      
    }
    return true;

    

    

    // return Promise.resolve(true);

    
  }

  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers['authorization']?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }
}

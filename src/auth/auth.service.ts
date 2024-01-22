import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { Model } from 'mongoose';
import { InjectModel } from '@nestjs/mongoose';
import { JwtService } from '@nestjs/jwt';
import { User } from './entities/user.entity';
import * as bcryptjs from 'bcryptjs';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { CreateUserDto } from './dto/create-user.dto';
import { LoginDto } from './dto/login.dto';
import { JwtPayload } from './interfaces/jwt-payload';



@Injectable()
export class AuthService {

   constructor(
    @InjectModel( User.name ) 
    private userModel: Model<User>,
    private jwtService: JwtService,   
   ) {}
  
  async create(createUserDto: CreateUserDto) {

    try {
      const {password, ...userData} = createUserDto;
      const newUser = new this.userModel({
        password:bcryptjs.hashSync(password,10),
        ...userData  
      });
       await newUser.save();
       const { password:_, ...user } = newUser.toJSON();
       return user;    
    } catch (error) {
      if (error.code === 11000) {        
        throw new BadRequestException(`${ createUserDto.email } Ya existe!`)        
      }
      throw new InternalServerErrorException('Something terribe happen!!!');      
    }
  }

  async login( loginDto: LoginDto ) {

    const { email, password } = loginDto;

    const user = await this.userModel.findOne({ email });
    if ( !user ) {
      throw new UnauthorizedException('Credenciales no validas - email');
    }
    
    if ( !bcryptjs.compareSync( password, user.password ) ) {
      throw new UnauthorizedException('Credenciales no validas - password');
    }

    const { password:_, ...rest  } = user.toJSON();

      
    return {
      user: rest,
      token: this.getJwtToken({ id: user.id }),
    }
  
  }

  findAll() {
    return `This action returns all auth`;
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  getJwtToken( payload: JwtPayload ) {
    const token = this.jwtService.sign(payload);
    return token;
  }
}

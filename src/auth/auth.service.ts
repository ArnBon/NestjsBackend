import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { Model } from 'mongoose';
import { InjectModel } from '@nestjs/mongoose';
import { JwtService } from '@nestjs/jwt';
import { User } from './entities/user.entity';
import * as bcryptjs from 'bcryptjs';
import { CreateUserDto, LoginDto, RegisterUserDto, UpdateAuthDto } from './dto';
import { JwtPayload } from './interfaces/jwt-payload';
import { LoginResponse } from './interfaces/login-response';




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

  async login( loginDto: LoginDto ):Promise<LoginResponse> {

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

  async register( registerDto: RegisterUserDto ): Promise<LoginResponse> {

    const user = await this.create( registerDto );
    console.log({user})

    return {
      user: user,
      token: this.getJwtToken({ id: user._id })
    }
  }

  findAll():Promise<User[]> {
    return this.userModel.find();
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

  async findUserById( id: string ) {
    const user = await this.userModel.findById( id );
    const { password, ...rest } = user.toJSON();
    return rest;
  }

  


  
}

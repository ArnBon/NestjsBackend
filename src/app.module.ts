import { Module } from '@nestjs/common';
import { AuthModule } from './auth/auth.module';
import { MongooseModule } from '@nestjs/mongoose';

@Module({
  imports: [
    AuthModule,    
    MongooseModule.forRoot( process.env.MONGO_URI ),
  ],
  controllers: [],
  providers: [],
})
export class AppModule {}

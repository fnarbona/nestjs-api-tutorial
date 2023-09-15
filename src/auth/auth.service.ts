import { ForbiddenException, Injectable } from '@nestjs/common';
import { AuthDto } from 'src/auth/dto';
import { PrismaService } from 'src/prisma/prisma.service';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
  ) {}

  async signup(dto: AuthDto) {
    // generate password hash
    const hash = await argon.hash(dto.password);
    // create user
    try {
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash,
        },
      });
      // return saved user
      return this.signToken(user.id, user.email);
    } catch (error) {
      // prisma will throw error if email is already taken
      if (error instanceof PrismaClientKnownRequestError) {
        // prisma error P2002 - Unique constraint failed
        if (error.code === 'P2002') {
          throw new ForbiddenException('Email already in use');
        }
      }
      throw error;
    }
  }

  async signin(dto: AuthDto) {
    // find user by email
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });
    // if user doesn't exist, throw error
    if (!user) throw new ForbiddenException('Invalid email or password');
    // compare password hash
    const pwMatches = await argon.verify(user.hash, dto.password);
    // if password incorrect, throw error
    if (!pwMatches) throw new ForbiddenException('Invalid email or password');
    // return user
    return this.signToken(user.id, user.email);
  }

  async signToken(
    userId: number,
    email: string,
  ): Promise<{ access_token: string }> {
    // generate payload from user data
    const payload = {
      sub: userId,
      email,
    };
    // generate token with payload, expiration time, and secret
    const token = await this.jwt.signAsync(payload, {
      expiresIn: process.env.JWT_EXPIRATION,
      secret: process.env.JWT_SECRET,
    });
    // return token
    return { access_token: token };
  }
}

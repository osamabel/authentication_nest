import {
  BadRequestException,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto/auth.dto';
import * as bcrypt from 'bcrypt';
import { Tokens } from './type/tokens.type';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
  ) {}

  /* ---------------------------------- LOGIN --------------------------------- */
  async login(dto: AuthDto): Promise<Tokens> {
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });
    if (!user) throw new ForbiddenException('Access Denied');
    const isPassword = await bcrypt.compare(dto.password, user.hash);
    if (!isPassword) throw new ForbiddenException('Access Denied');
    if (dto.name !== user.name) throw new ForbiddenException('Access Denied');
    if (dto.email !== user.email) throw new ForbiddenException('Access Denied');
    const tokens = await this.getTokens(user.id, user.email, user.name);
    await this.updateRefreshToken(user.id, tokens.refresh_token);
    return tokens;
  }
  /* ---------------------------------- LOGIN --------------------------------- */

  /* --------------------------------- SIGNUP --------------------------------- */
  async signup(dto: AuthDto): Promise<Tokens> {
    const userExists = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });
    if (userExists) {
      throw new BadRequestException('User already exists');
    }

    const hash = await bcrypt.hash(dto.password, 10);
    const newUser = await this.prisma.user.create({
      data: {
        name: dto.name,
        email: dto.email,
        hash: hash,
      },
    });

    const tokens = await this.getTokens(newUser.id, newUser.email, newUser.name);
    await this.updateRefreshToken(newUser.id, tokens.refresh_token);
    return tokens;
  }
  /* --------------------------------- SIGNUP --------------------------------- */

  /* --------------------------------- LOGOUT --------------------------------- */
  async logout(userId: string) {
    await this.prisma.user.update({
      where: {
        id: userId,
        hashRt: {
          not: null,
        },
      },
      data: {
        hashRt: null,
      },
    });
  }
  /* --------------------------------- LOGOUT --------------------------------- */

  /* --------------------------------- REFRECH -------------------------------- */
  async refresh(userId: string, rf_token: string): Promise<Tokens> {
    const user = await this.prisma.user.findUnique({
      where: {
        id: userId,
      },
    });
    console.log("user>>>" , user)
    if (!user || !user.hashRt) throw new ForbiddenException('Access Denied');
    const rt = await bcrypt.compare(rf_token, user.hashRt);
    if (!rt) throw new ForbiddenException('Access Denied');
    const tokens = await this.getTokens(user.id, user.email, user.name);
    await this.updateRefreshToken(user.id, tokens.refresh_token);
    return tokens;
  }
  /* --------------------------------- REFRECH -------------------------------- */

  async updateRefreshToken(userId: string, refreshToken: string) {
    const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);
    await this.prisma.user.update({
      where: {
        id: userId,
      },
      data: {
        hashRt: hashedRefreshToken,
      },
    });
  }

  async getTokens(userId: string, email: string, name: string): Promise<Tokens> {
    const [access_token, refresh_token] = await Promise.all([
      this.jwtService.signAsync(
        {
          sub: userId,
          name,
          email,
        },
        {
          secret: 'ACCESS_TOKEN_SECRET',
          expiresIn: '1m',
        },
        ),
        this.jwtService.signAsync(
          {
            sub: userId,
            name,
            email,
        },
        {
          secret: 'REFRESH_TOKEN_SECRET',
          expiresIn: '7d',
        },
      ),
    ]);

    return {
      access_token,
      refresh_token,
    };
  }
}

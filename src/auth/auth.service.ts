import { Injectable } from '@nestjs/common';

@Injectable({})
export class AuthService {
  signin(): string {
    return 'Signed in!';
  }
  signup(): string {
    return 'Signed up!';
  }
}

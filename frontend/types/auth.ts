import type { User, UserRole } from "@/types/user";

export interface LoginPayload {
  email: string;
  password: string;
}

export interface SignupPayload {
  name: string;
  email: string;
  password: string;
  passwordConfirm: string;
  role: Extract<UserRole, "user" | "provider">;
  address: string;
  phone?: string;
}

export interface AuthResponse {
  status: string;
  token: string;
  refreshToken?: string;
  data: {
    user: User;
  };
}


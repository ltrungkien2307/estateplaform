import { requestJson } from "@/services/apiClient";
import type { AuthResponse, LoginPayload, SignupPayload } from "@/types/auth";

export const authService = {
  signup(payload: SignupPayload) {
    return requestJson<AuthResponse, SignupPayload>("/auth/signup", {
      method: "POST",
      body: payload,
    });
  },
  login(payload: LoginPayload) {
    return requestJson<AuthResponse, LoginPayload>("/auth/login", {
      method: "POST",
      body: payload,
    });
  },
};


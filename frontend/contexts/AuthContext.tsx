import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";
import type { ReactNode } from "react";
import { ApiError } from "@/services/apiClient";
import { authService } from "@/services/authService";
import { userService } from "@/services/userService";
import type { LoginPayload, SignupPayload } from "@/types/auth";
import type { User } from "@/types/user";

const AUTH_STORAGE_KEY = "estate_manager_token";

interface AuthContextValue {
  user: User | null;
  token: string | null;
  isAuthLoading: boolean;
  login: (payload: LoginPayload) => Promise<void>;
  signup: (payload: SignupPayload) => Promise<void>;
  logout: () => void;
  refreshProfile: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

function normalizeError(error: unknown) {
  if (error instanceof ApiError) {
    throw error;
  }

  if (error instanceof Error) {
    throw new ApiError(error.message, 500);
  }

  throw new ApiError("Unknown authentication error", 500);
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [token, setToken] = useState<string | null>(null);
  const [user, setUser] = useState<User | null>(null);
  const [isAuthLoading, setIsAuthLoading] = useState(true);

  const persistToken = useCallback((nextToken: string | null) => {
    setToken(nextToken);
    if (typeof window === "undefined") {
      return;
    }

    if (!nextToken) {
      window.localStorage.removeItem(AUTH_STORAGE_KEY);
      return;
    }

    window.localStorage.setItem(AUTH_STORAGE_KEY, nextToken);
  }, []);

  const clearSession = useCallback(() => {
    persistToken(null);
    setUser(null);
  }, [persistToken]);

  const refreshProfile = useCallback(async () => {
    if (!token) {
      setUser(null);
      return;
    }

    try {
      const profile = await userService.getMe(token);
      setUser(profile);
    } catch (error) {
      clearSession();
      normalizeError(error);
    }
  }, [clearSession, token]);

  const login = useCallback(
    async (payload: LoginPayload) => {
      try {
        const response = await authService.login(payload);
        persistToken(response.token);
        setUser(response.data.user);
      } catch (error) {
        normalizeError(error);
      }
    },
    [persistToken]
  );

  const signup = useCallback(
    async (payload: SignupPayload) => {
      try {
        const response = await authService.signup(payload);
        persistToken(response.token);
        setUser(response.data.user);
      } catch (error) {
        normalizeError(error);
      }
    },
    [persistToken]
  );

  const logout = useCallback(() => {
    clearSession();
  }, [clearSession]);

  useEffect(() => {
    const initializeAuth = async () => {
      if (typeof window === "undefined") {
        setIsAuthLoading(false);
        return;
      }

      const savedToken = window.localStorage.getItem(AUTH_STORAGE_KEY);
      if (!savedToken) {
        setIsAuthLoading(false);
        return;
      }

      setToken(savedToken);
      try {
        const profile = await userService.getMe(savedToken);
        setUser(profile);
      } catch {
        clearSession();
      } finally {
        setIsAuthLoading(false);
      }
    };

    void initializeAuth();
  }, [clearSession]);

  const contextValue = useMemo<AuthContextValue>(
    () => ({
      user,
      token,
      isAuthLoading,
      login,
      signup,
      logout,
      refreshProfile,
    }),
    [isAuthLoading, login, logout, refreshProfile, signup, token, user]
  );

  return (
    <AuthContext.Provider value={contextValue}>{children}</AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used inside AuthProvider");
  }
  return context;
}


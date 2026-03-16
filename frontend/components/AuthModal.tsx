import { useEffect, useMemo, useState } from "react";
import type { InputHTMLAttributes, ReactNode } from "react";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { zodResolver } from "@hookform/resolvers/zod";
import {
  Building2,
  LoaderCircle,
  Lock,
  Mail,
  MapPin,
  Phone,
  User,
} from "lucide-react";
import { ApiError } from "@/services/apiClient";
import { useAuth } from "@/contexts/AuthContext";

type AuthMode = "login" | "signup";

interface AuthModalProps {
  isOpen: boolean;
  mode: AuthMode;
  onClose: () => void;
  onModeChange: (mode: AuthMode) => void;
}

const loginSchema = z.object({
  email: z.string().email("Please enter a valid email address."),
  password: z.string().min(1, "Password is required."),
});

const signupSchema = z
  .object({
    name: z.string().trim().min(2, "Name must be at least 2 characters.").max(100),
    email: z.string().trim().email("Please enter a valid email address."),
    password: z.string().min(8, "Password must be at least 8 characters."),
    passwordConfirm: z.string().min(1, "Please confirm your password."),
    role: z.enum(["user", "provider"]),
    address: z.string().trim().min(3, "Address must be at least 3 characters."),
    phone: z.string().trim().optional(),
  })
  .refine((values) => values.password === values.passwordConfirm, {
    message: "Password confirmation does not match password.",
    path: ["passwordConfirm"],
  });

type LoginValues = z.infer<typeof loginSchema>;
type SignupValues = z.infer<typeof signupSchema>;

function getErrorMessage(error: unknown) {
  if (error instanceof ApiError) {
    return error.message;
  }
  if (error instanceof Error) {
    return error.message;
  }
  return "Unable to complete this action right now. Please try again.";
}

function FieldError({ message }: { message?: string }) {
  if (!message) {
    return null;
  }
  return <p className="mt-1 text-xs text-rose-500">{message}</p>;
}

interface InputProps extends InputHTMLAttributes<HTMLInputElement> {
  icon: ReactNode;
}

function Input({ icon, ...props }: InputProps) {
  return (
    <label className="block">
      <span className="glass-input-wrapper">
        <span className="text-text-secondary">{icon}</span>
        <input className="glass-input" {...props} />
      </span>
    </label>
  );
}

export default function AuthModal({
  isOpen,
  mode,
  onClose,
  onModeChange,
}: AuthModalProps) {
  const { login, signup } = useAuth();
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [apiError, setApiError] = useState("");

  const loginForm = useForm<LoginValues>({
    resolver: zodResolver(loginSchema),
    defaultValues: { email: "", password: "" },
  });

  const signupForm = useForm<SignupValues>({
    resolver: zodResolver(signupSchema),
    defaultValues: {
      name: "",
      email: "",
      password: "",
      passwordConfirm: "",
      role: "user",
      address: "",
      phone: "",
    },
  });

  const isLoginMode = mode === "login";
  const title = useMemo(
    () => (isLoginMode ? "Welcome Back" : "Create Your Account"),
    [isLoginMode]
  );
  const subtitle = useMemo(
    () =>
      isLoginMode
        ? "Sign in to manage properties and transactions."
        : "Sign up as a user or provider to start with EstateManager.",
    [isLoginMode]
  );

  useEffect(() => {
    const onEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        onClose();
      }
    };
    if (isOpen) {
      window.addEventListener("keydown", onEscape);
      document.body.style.overflow = "hidden";
    }
    return () => {
      window.removeEventListener("keydown", onEscape);
      document.body.style.overflow = "";
    };
  }, [isOpen, onClose]);

  useEffect(() => {
    setApiError("");
    loginForm.clearErrors();
    signupForm.clearErrors();
  }, [loginForm, mode, signupForm]);

  useEffect(() => {
    if (!isOpen) {
      loginForm.reset();
      signupForm.reset();
      setApiError("");
    }
  }, [isOpen, loginForm, signupForm]);

  const submitLogin = loginForm.handleSubmit(async (values) => {
    setIsSubmitting(true);
    setApiError("");
    try {
      await login(values);
      onClose();
    } catch (error) {
      setApiError(getErrorMessage(error));
    } finally {
      setIsSubmitting(false);
    }
  });

  const submitSignup = signupForm.handleSubmit(async (values) => {
    setIsSubmitting(true);
    setApiError("");
    try {
      await signup({ ...values, phone: values.phone?.trim() || "" });
      onClose();
    } catch (error) {
      setApiError(getErrorMessage(error));
    } finally {
      setIsSubmitting(false);
    }
  });

  return (
    <div
      className={`fixed inset-0 z-50 flex items-center justify-center px-4 py-8 transition-all ${
        isOpen ? "pointer-events-auto opacity-100" : "pointer-events-none opacity-0"
      }`}
      style={{
        transitionDuration: "var(--transition-duration-normal)",
        transitionTimingFunction: "var(--transition-easing)",
      }}
      aria-hidden={!isOpen}
    >
      <button
        type="button"
        className="absolute inset-0 bg-text-primary/45 backdrop-blur-sm transition-opacity"
        onClick={onClose}
        aria-label="Close modal"
        style={{
          transitionDuration: "var(--transition-duration-normal)",
          transitionTimingFunction: "var(--transition-easing)",
        }}
      />

      <div
        className={`glass-panel relative z-10 w-full max-w-xl transition-all ${
          isOpen ? "translate-y-0 opacity-100 scale-100" : "translate-y-6 opacity-0 scale-95"
        }`}
        style={{
          transitionDuration: "var(--transition-duration-normal)",
          transitionTimingFunction: "var(--transition-easing)",
        }}
      >
        <div className="mb-6 flex items-center justify-between">
          <div>
            <h2 className="text-2xl font-semibold text-text-primary">{title}</h2>
            <p className="mt-1 text-sm text-text-secondary">{subtitle}</p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-full px-3 py-1 text-sm text-text-secondary transition-colors hover:bg-surface hover:text-text-primary"
          >
            Close
          </button>
        </div>

         <div className="mb-6 grid grid-cols-2 rounded-2xl border border-boundary bg-surface p-1 shadow-inner">
           <button
             type="button"
             onClick={() => onModeChange("login")}
             className={`rounded-xl px-4 py-2 text-sm font-medium transition-all ${
               isLoginMode
                 ? "bg-background-light text-text-primary shadow-sm"
                 : "text-text-secondary hover:text-text-primary"
             }`}
             style={{
               transitionDuration: "var(--transition-duration-fast)",
               transitionTimingFunction: "var(--transition-easing)",
             }}
           >
             Login
           </button>
           <button
             type="button"
             onClick={() => onModeChange("signup")}
             className={`rounded-xl px-4 py-2 text-sm font-medium transition-all ${
               !isLoginMode
                 ? "bg-background-light text-text-primary shadow-sm"
                 : "text-text-secondary hover:text-text-primary"
             }`}
             style={{
               transitionDuration: "var(--transition-duration-fast)",
               transitionTimingFunction: "var(--transition-easing)",
             }}
           >
             Signup
           </button>
         </div>

        {apiError ? (
          <div className="mb-4 rounded-xl border border-accent/20 bg-accent/10 px-4 py-3 text-sm text-accent">
            {apiError}
          </div>
        ) : null}

        {isLoginMode ? (
          <form onSubmit={submitLogin} className="space-y-4">
            <div>
              <Input
                icon={<Mail size={16} />}
                type="email"
                autoComplete="email"
                placeholder="Email address"
                {...loginForm.register("email")}
              />
              <FieldError message={loginForm.formState.errors.email?.message} />
            </div>

            <div>
              <Input
                icon={<Lock size={16} />}
                type="password"
                autoComplete="current-password"
                placeholder="Password"
                {...loginForm.register("password")}
              />
              <FieldError message={loginForm.formState.errors.password?.message} />
            </div>

            <button type="submit" className="glass-button-primary mt-2 w-full" disabled={isSubmitting}>
              {isSubmitting ? <LoaderCircle size={18} className="animate-spin" /> : "Login"}
            </button>
          </form>
        ) : (
          <form onSubmit={submitSignup} className="grid gap-4 md:grid-cols-2">
            <div className="md:col-span-2">
              <Input
                icon={<User size={16} />}
                type="text"
                autoComplete="name"
                placeholder="Full name"
                {...signupForm.register("name")}
              />
              <FieldError message={signupForm.formState.errors.name?.message} />
            </div>

            <div className="md:col-span-2">
              <Input
                icon={<Mail size={16} />}
                type="email"
                autoComplete="email"
                placeholder="Email address"
                {...signupForm.register("email")}
              />
              <FieldError message={signupForm.formState.errors.email?.message} />
            </div>

            <div>
              <Input
                icon={<Lock size={16} />}
                type="password"
                autoComplete="new-password"
                placeholder="Password"
                {...signupForm.register("password")}
              />
              <FieldError message={signupForm.formState.errors.password?.message} />
            </div>

            <div>
              <Input
                icon={<Lock size={16} />}
                type="password"
                autoComplete="new-password"
                placeholder="Confirm password"
                {...signupForm.register("passwordConfirm")}
              />
              <FieldError message={signupForm.formState.errors.passwordConfirm?.message} />
            </div>

            <div className="md:col-span-2">
              <Input
                icon={<MapPin size={16} />}
                type="text"
                autoComplete="street-address"
                placeholder="Address"
                {...signupForm.register("address")}
              />
              <FieldError message={signupForm.formState.errors.address?.message} />
            </div>

            <div>
              <Input
                icon={<Phone size={16} />}
                type="tel"
                autoComplete="tel"
                placeholder="Phone (optional)"
                {...signupForm.register("phone")}
              />
              <FieldError message={signupForm.formState.errors.phone?.message} />
            </div>

            <div>
              <label className="glass-input-wrapper">
                <span className="text-text-secondary">
                  <Building2 size={16} />
                </span>
                <select className="glass-input" {...signupForm.register("role")}>
                  <option value="user">User</option>
                  <option value="provider">Provider</option>
                </select>
              </label>
              <FieldError message={signupForm.formState.errors.role?.message} />
            </div>

            <button
              type="submit"
              className="glass-button-primary mt-2 w-full md:col-span-2"
              disabled={isSubmitting}
            >
              {isSubmitting ? <LoaderCircle size={18} className="animate-spin" /> : "Create account"}
            </button>
          </form>
        )}
      </div>
    </div>
  );
}


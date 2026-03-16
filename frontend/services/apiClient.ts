const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_URL?.replace(/\/$/, "") ||
  "http://localhost:5000/api";

interface RequestOptions<TBody = unknown> extends Omit<RequestInit, "body"> {
  token?: string | null;
  body?: TBody;
}

interface ApiErrorPayload {
  status?: string;
  message?: string;
  error?: string;
}

export class ApiError extends Error {
  statusCode: number;

  constructor(message: string, statusCode: number) {
    super(message);
    this.name = "ApiError";
    this.statusCode = statusCode;
  }
}

export async function requestJson<TResponse, TBody = unknown>(
  endpoint: string,
  options: RequestOptions<TBody> = {}
): Promise<TResponse> {
  const { token, body, headers, ...rest } = options;
  const isFormData = body instanceof FormData;

  const response = await fetch(`${API_BASE_URL}${endpoint}`, {
    ...rest,
    credentials: "include",
    headers: {
      ...(isFormData ? {} : { "Content-Type": "application/json" }),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(headers || {}),
    },
    body:
      body === undefined
        ? undefined
        : isFormData
          ? (body as FormData)
          : JSON.stringify(body),
  });

  const contentType = response.headers.get("content-type") || "";
  const isJson = contentType.includes("application/json");
  const payload = isJson ? ((await response.json()) as ApiErrorPayload) : null;

  if (!response.ok) {
    const message =
      payload?.message ||
      payload?.error ||
      "Something went wrong while processing your request.";
    throw new ApiError(message, response.status);
  }

  return (payload || ({} as TResponse)) as TResponse;
}


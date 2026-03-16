import { requestJson } from "@/services/apiClient";

export type SubscriptionPlan = "Pro" | "ProPlus";
export type PaymentMethod = "VNPay" | "PayPal";

interface CreateCheckoutPayload {
  subscriptionPlan: SubscriptionPlan;
  paymentMethod: PaymentMethod;
  amount?: number;
}

interface CreateCheckoutResponse {
  status: string;
  data: {
    checkoutUrl: string;
  };
}

interface SubscriptionInfo {
  plan: "Free" | SubscriptionPlan;
  expiryDate?: string;
  isActive: boolean;
  createdAt?: string;
}

export const paymentService = {
  async createCheckout(payload: CreateCheckoutPayload, redirect: boolean = false) {
    const params = new URLSearchParams();
    params.set("redirect", String(redirect));
    const query = params.toString() ? `?${params.toString()}` : "";
    return requestJson<CreateCheckoutResponse>(`/payments/create-checkout${query}`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
  },

  // Subscription plans pricing
  SUBSCRIPTION_PLANS: {
    Pro: {
      name: "Pro",
      price: 199000,
      pricingDisplay: "199,000₫/tháng",
      duration: 30,
      features: [
        "Đăng tối đa 10 bất động sản",
        "Ưu tiên hiển thị cao",
        "Phân tích chi tiết",
        "Hỗ trợ ưu tiên",
      ],
    },
    ProPlus: {
      name: "Pro Plus",
      price: 499000,
      pricingDisplay: "499,000₫/tháng",
      duration: 30,
      features: [
        "Đăng tối đa 50 bất động sản",
        "Ưu tiên hiển thị tối cao",
        "Phân tích chi tiết + AI insights",
        "Hỗ trợ VIP 24/7",
        "Quản lý đại lý",
      ],
    },
  } as Record<SubscriptionPlan, any>,
};

export default paymentService;
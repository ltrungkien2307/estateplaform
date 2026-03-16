import { useEffect, useState } from "react";
import { useRouter } from "next/router";
import Layout from "@/components/Layout";
import PlanCard from "@/components/PlanCard";
import { paymentService, type SubscriptionPlan } from "@/services/paymentService";
import { useAuth } from "@/contexts/AuthContext";
import type { User } from "@/types/user";

export default function SubscriptionPlans() {
  const router = useRouter();
  const { user, isAuthLoading } = useAuth();
  const [selectedPlan, setSelectedPlan] = useState<SubscriptionPlan | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!isAuthLoading) {
      setLoading(false);
    }
  }, [isAuthLoading]);

  const handleSelectPlan = (plan: SubscriptionPlan) => {
    setSelectedPlan(plan);
    router.push(`/subscription/checkout?plan=${plan}`);
  };

  if (loading) {
    return (
      <Layout>
        <div className="flex justify-center items-center min-h-screen">
          <div className="text-center">
            <div className="inline-block animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-600"></div>
            <p className="mt-4 text-gray-700">Đang tải...</p>
          </div>
        </div>
      </Layout>
    );
  }

  return (
    <Layout>
      <div className="container mx-auto px-4 py-8 max-w-6xl">
        <div className="text-center mb-12">
          <h1 className="text-4xl font-bold text-gray-900 mb-4">Các gói dịch vụ</h1>
          <p className="text-lg text-gray-600">
            Nâng cấp gói để mở khóa các tính năng vượt trội
          </p>
        </div>

        {/* Current Plan Info */}
        {user && (
          <div className="bg-blue-50 border border-blue-200 rounded-lg p-6 mb-8">
            <p className="text-blue-900">
              <span className="font-semibold">Gói hiện tại:</span>{" "}
              <span className="text-lg font-bold text-blue-600">
                {user.subscription?.plan || "Free"}
              </span>
            </p>
          </div>
        )}

        {/* Plans Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-6 mb-12">
          {/* Free Plan */}
          <div className="rounded-lg border-2 border-gray-400 overflow-hidden shadow">
            <div className="p-6">
              <h3 className="text-xl font-bold text-gray-900 mb-2">Miễn phí</h3>
              <p className="text-3xl font-bold text-gray-400 mb-4">0₫</p>

              <ul className="space-y-3 mb-6">
                <li className="flex items-start gap-2 text-sm text-gray-700">
                  <span className="text-green-500 font-bold">✓</span>
                  <span>Đăng tối đa 3 bất động sản</span>
                </li>
                <li className="flex items-start gap-2 text-sm text-gray-700">
                  <span className="text-green-500 font-bold">✓</span>
                  <span>Tìm kiếm cơ bản</span>
                </li>
                <li className="flex items-start gap-2 text-sm text-gray-700">
                  <span className="text-green-500 font-bold">✓</span>
                  <span>Hỗ trợ email</span>
                </li>
              </ul>

              <button
                disabled={!user || user.subscription?.plan === "Free"}
                className="w-full py-2 rounded-lg font-semibold bg-gray-400 text-white opacity-50 cursor-not-allowed"
              >
                {user?.subscription?.plan === "Free" ? "Gói hiện tại" : "Gói miễn phí"}
              </button>
            </div>
          </div>

          {/* Pro Plan */}
          <PlanCard
            plan="Pro"
            name={paymentService.SUBSCRIPTION_PLANS.Pro.name}
            price={paymentService.SUBSCRIPTION_PLANS.Pro.pricingDisplay}
            features={paymentService.SUBSCRIPTION_PLANS.Pro.features}
            onSelect={handleSelectPlan}
            isSelected={selectedPlan === "Pro"}
            isCurrentPlan={user?.subscription?.plan === "Pro"}
          />

          {/* Pro Plus Plan */}
          <PlanCard
            plan="ProPlus"
            name={paymentService.SUBSCRIPTION_PLANS.ProPlus.name}
            price={paymentService.SUBSCRIPTION_PLANS.ProPlus.pricingDisplay}
            features={paymentService.SUBSCRIPTION_PLANS.ProPlus.features}
            onSelect={handleSelectPlan}
            isSelected={selectedPlan === "ProPlus"}
            isCurrentPlan={user?.subscription?.plan === "ProPlus"}
          />
        </div>

        {/* FAQ Section */}
        <div className="bg-white rounded-lg shadow-md p-8">
          <h2 className="text-2xl font-bold text-gray-900 mb-6">Câu hỏi thường gặp</h2>

          <div className="space-y-6">
            <div>
              <h3 className="font-semibold text-gray-900 mb-2">Tôi có thể nâng cấp hoặc hạ cấp bất kỳ lúc nào không?</h3>
              <p className="text-gray-700">Có, bạn có thể thay đổi gói dịch vụ của mình bất kỳ lúc nào.</p>
            </div>

            <div>
              <h3 className="font-semibold text-gray-900 mb-2">Thanh toán như thế nào?</h3>
              <p className="text-gray-700">
                Chúng tôi hỗ trợ hai phương thức thanh toán: VNPay (chuyển khoản ngân hàng) và PayPal.
              </p>
            </div>

            <div>
              <h3 className="font-semibold text-gray-900 mb-2">Tôi có thể hủy đăng ký không?</h3>
              <p className="text-gray-700">
                Có, bạn có thể hủy đăng ký của mình bất kỳ lúc nào. Bạn sẽ mất quyền truy cập vào các tính năng được thanh toán
                từ ngày hủy.
              </p>
            </div>

            <div>
              <h3 className="font-semibold text-gray-900 mb-2">Còn các bất động sản của tôi thì sao?</h3>
              <p className="text-gray-700">
                Các bất động sản của bạn vẫn được lưu giữ. Nếu bạn hạ cấp về Free, bạn chỉ có thể hiển thị 3 bất động sản công khai.
              </p>
            </div>
          </div>
        </div>
      </div>
    </Layout>
  );
}

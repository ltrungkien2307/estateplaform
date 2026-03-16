import { useEffect, useState } from "react";
import { useRouter } from "next/router";
import Layout from "@/components/Layout";
import StatCard from "@/components/StatCard";
import { adminService } from "@/services/adminService";
import { useAuth } from "@/contexts/AuthContext";
import Link from "next/link";

interface DashboardStats {
  totalUsers: number;
  totalProviders: number;
  totalProperties: number;
  totalPropertyApprovals: number;
  totalPropertyRejections: number;
  totalVerifiedProviders: number;
  totalPendingProviders: number;
  totalRejectedProviders: number;
  pendingPropertiesCount: number;
}

export default function AdminDashboard() {
  const router = useRouter();
  const { user, isAuthLoading } = useAuth();
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const initDashboard = async () => {
      try {
        if (!user || user.role !== "admin") {
          router.push("/");
          return;
        }

        const response = await adminService.getDashboardStats();
        setStats(response.data);
      } catch (error) {
        console.error("Error loading dashboard:", error);
      } finally {
        setLoading(false);
      }
    };

    if (!isAuthLoading) {
      initDashboard();
    }
  }, [router, user, isAuthLoading]);

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
        <h1 className="text-3xl font-bold text-gray-900 mb-8">Bảng điều khiển Admin</h1>

        {/* Key Metrics */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
          <StatCard icon="👥" title="Tổng người dùng" value={stats?.totalUsers || 0} />
          <StatCard icon="🏢" title="Nhà cung cấp" value={stats?.totalProviders || 0} />
          <StatCard icon="🏠" title="Tổng bất động sản" value={stats?.totalProperties || 0} />
          <StatCard icon="⏳" title="Chờ phê duyệt" value={stats?.pendingPropertiesCount || 0} trend="up" />
        </div>

        {/* Property Stats */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-8">
          <StatCard icon="✓" title="Bất động sản đã phê duyệt" value={stats?.totalPropertyApprovals || 0} trend="up" />
          <StatCard icon="✗" title="Bất động sản bị từ chối" value={stats?.totalPropertyRejections || 0} />
        </div>

        {/* Provider Verification Stats */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-8">
          <StatCard icon="✓" title="Nhà cung cấp đã xác minh" value={stats?.totalVerifiedProviders || 0} />
          <StatCard icon="⏳" title="Chờ xác minh" value={stats?.totalPendingProviders || 0} trend="up" />
          <StatCard icon="✗" title="Bị từ chối" value={stats?.totalRejectedProviders || 0} />
        </div>

        {/* Action Buttons */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 mb-8">
          <Link
            href="/admin/properties/pending"
            className="p-6 bg-red-100 text-red-900 rounded-lg font-semibold hover:bg-red-200 transition text-center"
          >
            📋 Duyệt bất động sản ({stats?.pendingPropertiesCount || 0})
          </Link>
          <Link
            href="/admin/providers/pending"
            className="p-6 bg-yellow-100 text-yellow-900 rounded-lg font-semibold hover:bg-yellow-200 transition text-center"
          >
            👤 Xác minh nhà cung cấp ({stats?.totalPendingProviders || 0})
          </Link>
          <Link
            href="/admin/kyc-management"
            className="p-6 bg-blue-100 text-blue-900 rounded-lg font-semibold hover:bg-blue-200 transition text-center"
          >
            🆔 Quản lý KYC
          </Link>
        </div>

        {/* Quick Info */}
        <div className="bg-white rounded-lg shadow-md p-6">
          <h2 className="text-xl font-bold text-gray-900 mb-4">Tóm tắt hệ thống</h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-6">
            <div>
              <h3 className="font-semibold text-gray-900 mb-2">Người dùng</h3>
              <ul className="space-y-1 text-sm text-gray-700">
                <li>Tổng: <span className="font-semibold">{stats?.totalUsers || 0}</span></li>
                <li>Nhà cung cấp: <span className="font-semibold">{stats?.totalProviders || 0}</span></li>
              </ul>
            </div>
            <div>
              <h3 className="font-semibold text-gray-900 mb-2">Bất động sản</h3>
              <ul className="space-y-1 text-sm text-gray-700">
                <li>Tổng: <span className="font-semibold">{stats?.totalProperties || 0}</span></li>
                <li>Chờ phê duyệt: <span className="font-semibold">{stats?.pendingPropertiesCount || 0}</span></li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </Layout>
  );
}

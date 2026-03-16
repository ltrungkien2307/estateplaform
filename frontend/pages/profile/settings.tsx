import { useEffect, useState } from "react";
import { useRouter } from "next/router";
import Layout from "@/components/Layout";
import { useAuth } from "@/contexts/AuthContext";
import { userService } from "@/services/userService";
import type { User } from "@/types/user";
import Image from "next/image";

interface UpdateFormData {
  name: string;
  phone: string;
  address: string;
  avatar: string;
}

export default function ProfileSettings() {
  const router = useRouter();
  const { user: authUser, isAuthLoading } = useAuth();
  const [user, setUser] = useState<User | null>(null);
  const [formData, setFormData] = useState<UpdateFormData>({
    name: "",
    phone: "",
    address: "",
    avatar: "",
  });
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<{ type: "success" | "error"; text: string } | null>(null);

  useEffect(() => {
    if (!isAuthLoading) {
      if (!authUser) {
        router.push("/");
      } else {
        setUser(authUser);
        setFormData({
          name: authUser.name || "",
          phone: authUser.phone || "",
          address: authUser.address || "",
          avatar: authUser.avatar || "",
        });
        setLoading(false);
      }
    }
  }, [authUser, isAuthLoading, router]);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setFormData((prev) => ({ ...prev, [name]: value }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setSaving(true);
      const token = typeof window !== "undefined" ? localStorage.getItem("token") || "" : "";
      await userService.updateMe(token, formData);
      setMessage({ type: "success", text: "Cập nhật hồ sơ thành công!" });
      setTimeout(() => setMessage(null), 3000);
    } catch (error: any) {
      setMessage({ type: "error", text: error.message || "Lỗi khi cập nhật hồ sơ" });
    } finally {
      setSaving(false);
    }
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
      <div className="container mx-auto px-4 py-8 max-w-2xl">
        <h1 className="text-3xl font-bold text-gray-900 mb-2">Cài đặt hồ sơ</h1>
        <p className="text-gray-600 mb-8">Cập nhật thông tin cá nhân của bạn</p>

        <div className="bg-white rounded-lg shadow-md p-6">
          {message && (
            <div
              className={`p-4 rounded-lg mb-6 ${
                message.type === "success"
                  ? "bg-green-100 text-green-700"
                  : "bg-red-100 text-red-700"
              }`}
            >
              {message.text}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-6">
            {/* Avatar Preview */}
            {formData.avatar && (
              <div className="text-center">
                <div className="relative w-24 h-24 rounded-full overflow-hidden mx-auto mb-4 bg-gray-200">
                  <Image src={formData.avatar} alt="Avatar" fill className="object-cover" />
                </div>
              </div>
            )}

            {/* Name */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Tên</label>
              <input
                type="text"
                name="name"
                value={formData.name}
                onChange={handleChange}
                className="w-full px-4 py-2 rounded-lg border border-gray-300 focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="Nhập tên của bạn"
              />
            </div>

            {/* Phone */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Số điện thoại</label>
              <input
                type="tel"
                name="phone"
                value={formData.phone}
                onChange={handleChange}
                className="w-full px-4 py-2 rounded-lg border border-gray-300 focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="Nhập số điện thoại"
              />
            </div>

            {/* Address */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Địa chỉ</label>
              <input
                type="text"
                name="address"
                value={formData.address}
                onChange={handleChange}
                className="w-full px-4 py-2 rounded-lg border border-gray-300 focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="Nhập địa chỉ của bạn"
              />
            </div>

            {/* Avatar URL */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Avatar URL</label>
              <input
                type="url"
                name="avatar"
                value={formData.avatar}
                onChange={handleChange}
                className="w-full px-4 py-2 rounded-lg border border-gray-300 focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="Nhập URL avatar của bạn"
              />
            </div>

            {/* Account Info */}
            <div className="p-4 bg-gray-100 rounded-lg">
              <h3 className="font-semibold text-gray-900 mb-3">Thông tin tài khoản</h3>
              <div className="space-y-2 text-sm">
                <p>
                  <span className="text-gray-600">Email:</span>{" "}
                  <span className="font-semibold">{user?.email}</span>
                </p>
                <p>
                  <span className="text-gray-600">Vai trò:</span>{" "}
                  <span className="font-semibold capitalize">
                    {user?.role === "user" && "Người dùng"}
                    {user?.role === "provider" && "Nhà cung cấp"}
                    {user?.role === "admin" && "Quản trị viên"}
                  </span>
                </p>
                <p>
                  <span className="text-gray-600">Ngày tạo:</span>{" "}
                  <span className="font-semibold">
                    {user?.createdAt ? new Date(user.createdAt).toLocaleDateString("vi-VN") : "N/A"}
                  </span>
                </p>
              </div>
            </div>

            {/* Submit Button */}
            <button
              type="submit"
              disabled={saving}
              className="w-full bg-blue-600 text-white rounded-lg py-2 font-semibold hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition"
            >
              {saving ? "Đang lưu..." : "Cập nhật hồ sơ"}
            </button>
          </form>

          {/* Additional Options */}
          <div className="mt-8 pt-8 border-t">
            <h3 className="font-semibold text-gray-900 mb-4">Cài đặt khác</h3>
            <div className="space-y-2">
              <a
                href="/profile/change-password"
                className="block p-3 text-blue-600 hover:bg-gray-100 rounded-lg transition"
              >
                🔐 Đổi mật khẩu
              </a>
              {user?.role === "provider" && (
                <a
                  href="/provider/dashboard"
                  className="block p-3 text-blue-600 hover:bg-gray-100 rounded-lg transition"
                >
                  📊 Bảng điều khiển nhà cung cấp
                </a>
              )}
              {user?.role === "admin" && (
                <a
                  href="/admin/dashboard"
                  className="block p-3 text-blue-600 hover:bg-gray-100 rounded-lg transition"
                >
                  ⚙️ Bảng điều khiển quản trị
                </a>
              )}
            </div>
          </div>
        </div>
      </div>
    </Layout>
  );
}

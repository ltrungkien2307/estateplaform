# Kế hoạch Thiết kế lại Giao diện Frontend (EstateManager)

**Mục tiêu:** Thiết kế lại toàn bộ giao diện Frontend của dự án 'EstateManager' trong thư mục `C:\Users\tkien\Downloads\estateplaform\frontend` theo hệ thống thiết kế và phong cách thị giác Glassmorphism & Minimalist, hiện đại, sạch sẽ, chuyên nghiệp, nhất quán.

**Yêu cầu CRITICAL:**
*   **TUYỆT ĐỐI KHÔNG SỬ DỤNG EMOJI** trong bất kỳ thành phần UI nào.
*   Đảm bảo tất cả các thay đổi UI phải được triển khai trong thư mục `C:\Users\tkien\Downloads\estateplaform\frontend`.
*   Sử dụng **Tailwind CSS** để triển khai hệ thống thiết kế, tận dụng tối đa khả năng tùy chỉnh theme của `tailwind.config.js` cho màu sắc, font chữ, khoảng cách, bo góc và bóng đổ.
*   **KHÔNG THỰC HIỆN BẤT KỲ CHỨC NĂNG BACKEND NÀO**, chỉ tập trung vào việc điều chỉnh giao diện Frontend.

---

## 1. Design Philosophy

*   **Loại phong cách thiết kế:** Glassmorphism & Minimalist (sử dụng hiệu ứng mờ tinh tế, đổ bóng nhẹ và khoảng trắng rộng rãi).
*   **Tone thị giác tổng thể và tính cách thương hiệu:** Hiện đại, Sạch sẽ, Chuyên nghiệp, tập trung vào sự rõ ràng và dễ sử dụng.

## 2. Reusable Design Tokens (Cấu hình trong `tailwind.config.js` hoặc các file CSS biến)

*   **Colors:**
    *   `--color-primary-light`
    *   `--color-primary-dark`
    *   `--color-secondary`
    *   `--color-accent`
    *   `--color-background-light`
    *   `--color-background-dark` (nếu có)
    *   `--color-surface`
    *   `--color-text-primary`
    *   `--color-text-secondary`
    *   `--color-border`
*   **Font Families:** Chọn font sans-serif hiện đại, chuyên nghiệp (ví dụ: Inter, Poppins, Manrope).
*   **Font Sizes:**
    *   `--font-size-h1`, `--font-size-h2`, `--font-size-h3`
    *   `--font-size-body-large`, `--font-size-body-medium`, `--font-size-body-small`
*   **Spacing Units (dựa trên một base unit, ví dụ 4px hoặc 8px):**
    *   `--spacing-xs`, `--spacing-sm`, `--spacing-md`, `--spacing-lg`, `--spacing-xl`
*   **Border Radius:**
    *   `--border-radius-sm`, `--border-radius-md`, `--border-radius-lg`
*   **Shadows:**
    *   `--shadow-sm` (subtle), `--shadow-md`, `--shadow-lg` (cho modals)
*   **Transitions:**
    *   `--transition-duration-fast`, `--transition-duration-normal`
    *   `--transition-easing` (ví dụ: ease-in-out)

---

## Các Giai đoạn Thực hiện:

### Giai đoạn 1: Thiết lập và Phong cách Toàn cục (Setup & Global Styles)

**Mục tiêu:** Xây dựng nền tảng cho hệ thống thiết kế toàn cục.

**Các bước:**
1.  **Cấu hình Tailwind CSS (`tailwind.config.js`):**
    *   Tùy chỉnh theme với các `Design Tokens` đã cung cấp (màu sắc, font chữ, khoảng cách, bo góc, bóng đổ, transitions).
    *   Đảm bảo cấu hình cho các hiệu ứng Glassmorphism (ví dụ: `backdrop-filter` cho blur).
2.  **Thiết lập Global CSS (`globals.css` hoặc tương đương):**
    *   Cài đặt các reset CSS cơ bản.
    *   Import các font chữ tùy chỉnh đã chọn.
    *   Đảm bảo các styles cơ bản tuân thủ `Design Principles`.
3.  **Refine Core Layout Component (`frontend/components/Layout.tsx`):**
    *   Đảm bảo responsive navigation bar (header) với logo, user profile dropdown (login/signup/profile links) và global footer được tạo kiểu theo `Design Principles`.
    *   Kiểm tra tính linh hoạt của layout để phù hợp với các sidebar trong tương lai.
    *   Sử dụng `Spacing Units` và `Color System` đã định nghĩa.

### Giai đoạn 2: Tinh chỉnh các Component cốt lõi (Core Components Refinement)

**Mục tiêu:** Đảm bảo các thành phần UI cơ bản nhất quán và tuân thủ hệ thống thiết kế.

**Các bước:**
1.  **Buttons:**
    *   Điều chỉnh visual style: hiệu ứng mờ nhẹ, đổ bóng tinh tế.
    *   Áp dụng `Spacing Units`, `Border Radius`, `Shadows` đã định nghĩa.
    *   Triển khai `Hover/active states` với `Transitions` mượt mà.
2.  **Inputs:**
    *   Điều chỉnh visual style: sạch sẽ, hiệu ứng glassmorphism.
    *   Áp dụng `Spacing Units`, `Border Radius`, `Shadows`.
    *   Triển khai `Hover/active states` mượt mà (ví dụ: viền nổi bật).
3.  **Cards (ví dụ: ListingCard.tsx):**
    *   Điều chỉnh visual style: kết hợp glassmorphism với các yếu tố sạch sẽ, hiện đại.
    *   Áp dụng `Spacing Units` (cho padding bên trong), `Border Radius`, `Shadows`.
    *   Triển khai `Hover/active states` (ví dụ: nâng nhẹ hoặc đổ bóng tăng cường).
4.  **Modals (ví dụ: AuthModal.tsx):**
    *   Điều chỉnh visual style: nền sạch, hiệu ứng mờ kính hoặc lớp phủ bán trong suốt.
    *   Áp dụng `Spacing Units`, `Border Radius`, `Shadows` (rõ ràng hơn một chút).
5.  **Dropdowns:**
    *   Điều chỉnh visual style: sạch sẽ, menu thả xuống rõ ràng, phù hợp glassmorphism.
    *   Áp dụng `Spacing Units`, `Border Radius`, `Shadows`.
    *   Triển khai `Hover/active states`.
6.  **Tables:**
    *   Điều chỉnh visual style: sạch sẽ, dễ đọc, phân tách các hàng rõ ràng.
    *   Áp dụng `Spacing Units` cho padding trong các ô.
    *   Triển khai `Hover states` cho các hàng.
7.  **Iconography:**
    *   Đảm bảo tất cả các icon sử dụng thư viện vector chuyên nghiệp (Lucide React, React Icons từ Font Awesome/Material Design) và được tạo kiểu nhất quán.

### Giai đoạn 3: Tinh chỉnh Giao diện theo trang (Page-Specific UI Refinement)

**Mục tiêu:** Điều chỉnh giao diện các trang cụ thể để tuân thủ hệ thống thiết kế toàn cục.

**Các bước:**
1.  **Homepage (`frontend/pages/index.tsx`):**
    *   Đảm bảo hero section, AdvancedSearchBar.tsx, ListingCard.tsx được tích hợp và tạo kiểu theo `Design Principles`.
    *   Áp dụng `Spacing Units` và `Typography` nhất quán.
2.  **Authentication UI (`frontend/components/AuthModal.tsx` & Pages):**
    *   Đảm bảo input fields, validation feedback, error handling messages được tạo kiểu theo `Design Principles` và `Component System`.
3.  **Property Detail Page (`frontend/pages/properties/[id].tsx`):**
    *   Điều chỉnh Image Carousel/Gallery, Title, Description, Price, Detailed Address, Property Attributes, Provider Information, "Contact Provider" button/form để phù hợp với hệ thống thiết kế.
    *   Đảm bảo placeholder cho bản đồ Leaflet cũng tuân thủ phong cách.
4.  **KYC Submission Page (`frontend/pages/profile/kyc.tsx` hoặc `frontend/pages/user/kyc.tsx`):**
    *   Điều chỉnh hiển thị `kycStatus`, `isVerified`, `kycRejectionReason`.
    *   Thiết kế lại File Upload Component (drag-and-drop/click-to-upload, image previews, instructions) để phù hợp `Design Principles`.
    *   Đảm bảo input field `declaredIdNumber` và hiển thị `kycDocuments` nhất quán.
5.  **Admin KYC Management Page (`frontend/pages/admin/kyc-management.tsx`):**
    *   Điều chỉnh List of Users/Providers (table, filtering/sorting) và KYC Detail View (modal/sidebar) để phù hợp với hệ thống thiết kế.
    *   Đảm bảo các action buttons ("Approve KYC", "Reject KYC") và input `kycRejectionReason` tuân thủ `Component System`.

### Giai đoạn 4: Tương tác và Hoàn thiện (Interaction & Polish)

**Mục tiêu:** Đảm bảo trải nghiệm người dùng mượt mà và trực quan.

**Các bước:**
1.  **Animations & Transitions:**
    *   Kiểm tra và điều chỉnh tất cả các hoạt ảnh và chuyển đổi trang để sử dụng `ease-in-out` với `Transition Tokens`.
    *   Đảm bảo chúng mượt mà và tinh tế, không gây xao nhãng.
2.  **Micro-interactions:**
    *   Xác định và triển khai các micro-interactions nhỏ để nâng cao trải nghiệm người dùng (ví dụ: phản hồi khi click nút, hover trên các mục).
3.  **Responsive Design:**
    *   Kiểm tra kỹ lưỡng giao diện trên các kích thước màn hình khác nhau để đảm bảo tính đáp ứng hoàn chỉnh.
    *   Điều chỉnh `Layout Structure` và `Spacing Units` khi cần thiết cho các breakpoint khác nhau.

### Giai đoạn 5: Đánh giá và Tối ưu hóa (Review & Optimization)

**Mục tiêu:** Đảm bảo chất lượng cuối cùng và hiệu suất.

**Các bước:**
1.  **Kiểm tra chéo thiết kế:** So sánh giao diện hiện tại với `Design Principles` và `Design Tokens` để đảm bảo tính nhất quán tuyệt đối.
2.  **Đánh giá hiệu suất:** Kiểm tra hiệu suất UI, đặc biệt là loading ảnh và các hoạt ảnh nặng.
3.  **Tối ưu hóa mã:** Đảm bảo mã Tailwind CSS và React/Next.js sạch sẽ, dễ đọc và tuân thủ các best practices.
4.  **Báo cáo:** Cung cấp báo cáo về các thay đổi đã thực hiện và xác nhận rằng tất cả các yêu cầu đã được đáp ứng.

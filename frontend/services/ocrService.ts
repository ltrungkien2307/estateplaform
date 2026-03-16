export type OcrSideLabel = "front" | "back" | "unknown";

export interface OcrProcessResponse {
  status: "success";
  side_label: string;
  confidence_score: number;
  raw_text: string;
  extracted_data: {
    fullName?: string;
    idNumber?: string;
    dateOfBirth?: string;
    permanentAddress?: string;
    placeOfOrigin?: string;
  };
  field_confidences: Record<string, number>;
  processing_meta: {
    card_detected: boolean;
    deskew_angle: number;
    image_used_for_ocr: string;
    line_count: number;
    processing_time_ms: number;
  };
}

interface OcrErrorResponse {
  status?: string;
  message?: string;
  detail?: string;
}

const OCR_ENDPOINT =
  process.env.NEXT_PUBLIC_KYC_PYTHON_SERVICE_URL || "http://localhost:8001/process";

export async function processOcrImage(
  file: File,
  sideLabel: OcrSideLabel
): Promise<OcrProcessResponse> {
  const payload = new FormData();
  payload.append("file", file);
  payload.append("side_label", sideLabel);

  const response = await fetch(OCR_ENDPOINT, {
    method: "POST",
    body: payload,
  });

  const contentType = response.headers.get("content-type") || "";
  const isJson = contentType.includes("application/json");
  const data = (isJson ? await response.json() : null) as OcrProcessResponse | OcrErrorResponse | null;

  if (!response.ok) {
    const errorMessage =
      (data as OcrErrorResponse | null)?.message ||
      (data as OcrErrorResponse | null)?.detail ||
      "OCR processing request failed.";
    throw new Error(errorMessage);
  }

  return data as OcrProcessResponse;
}

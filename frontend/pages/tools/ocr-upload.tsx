import { useEffect, useMemo, useRef, useState } from "react";
import type { DragEvent } from "react";
import Image from "next/image";
import { FileUp, LoaderCircle, UploadCloud, X } from "lucide-react";
import Layout from "@/components/Layout";
import type { OcrProcessResponse, OcrSideLabel } from "@/services/ocrService";
import { processOcrImage } from "@/services/ocrService";

const ACCEPTED_TYPES = ["image/jpeg", "image/png"];
const MAX_FILE_SIZE = 12 * 1024 * 1024;

function validateImage(file: File) {
  if (!ACCEPTED_TYPES.includes(file.type)) {
    return "Only JPG and PNG images are supported.";
  }

  if (file.size > MAX_FILE_SIZE) {
    return "Image size must be 12MB or less.";
  }

  return null;
}

export default function OcrUploadPage() {
  const [file, setFile] = useState<File | null>(null);
  const [preview, setPreview] = useState<string | null>(null);
  const [sideLabel, setSideLabel] = useState<OcrSideLabel>("front");
  const [loading, setLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [result, setResult] = useState<OcrProcessResponse | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (!file) {
      setPreview(null);
      return;
    }

    const objectUrl = URL.createObjectURL(file);
    setPreview(objectUrl);
    return () => URL.revokeObjectURL(objectUrl);
  }, [file]);

  const canSubmit = useMemo(() => Boolean(file && !loading), [file, loading]);

  const handleSelectFile = (selectedFile: File) => {
    const validationError = validateImage(selectedFile);
    if (validationError) {
      setErrorMessage(validationError);
      return;
    }

    setErrorMessage(null);
    setResult(null);
    setFile(selectedFile);
  };

  const handleDrop = (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    const droppedFile = event.dataTransfer.files?.[0];
    if (droppedFile) {
      handleSelectFile(droppedFile);
    }
  };

  const handleClearFile = () => {
    setFile(null);
    setErrorMessage(null);
    setResult(null);
    if (inputRef.current) {
      inputRef.current.value = "";
    }
  };

  const handleProcess = async () => {
    if (!file) {
      setErrorMessage("Please select an image before processing.");
      return;
    }

    setLoading(true);
    setErrorMessage(null);
    setResult(null);

    try {
      const processed = await processOcrImage(file, sideLabel);
      setResult(processed);
    } catch (error) {
      if (error instanceof Error) {
        setErrorMessage(error.message);
      } else {
        setErrorMessage("Unable to process OCR at the moment.");
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <Layout>
      <div className="space-y-6">
        <section className="glass-panel">
          <h1 className="text-2xl font-semibold text-slate-900">CCCD OCR Upload</h1>
          <p className="mt-2 text-sm text-slate-600">
            Upload one CCCD image to test OCR extraction from `kyc-python-service`.
          </p>

          <div className="mt-5 space-y-4">
            <label className="flex flex-col gap-2">
              <span className="text-xs font-semibold uppercase tracking-wide text-slate-500">Document Side</span>
              <select
                className="glass-input rounded-xl border border-white/70 bg-white/80 px-3 py-2"
                value={sideLabel}
                onChange={(event) => setSideLabel(event.target.value as OcrSideLabel)}
              >
                <option value="front">Front</option>
                <option value="back">Back</option>
                <option value="unknown">Unknown</option>
              </select>
            </label>

            <div
              role="button"
              tabIndex={0}
              onClick={() => inputRef.current?.click()}
              onDrop={handleDrop}
              onDragOver={(event) => event.preventDefault()}
              onKeyDown={(event) => {
                if (event.key === "Enter" || event.key === " ") {
                  inputRef.current?.click();
                }
              }}
              className="cursor-pointer rounded-2xl border border-dashed border-slate-300 bg-white/70 p-4 transition-colors hover:border-slate-500 hover:bg-white"
            >
              <input
                ref={inputRef}
                type="file"
                accept=".jpg,.jpeg,.png,image/jpeg,image/png"
                className="hidden"
                onChange={(event) => {
                  const selectedFile = event.target.files?.[0];
                  if (selectedFile) {
                    handleSelectFile(selectedFile);
                  }
                }}
              />

              {preview ? (
                <div className="relative">
                  <button
                    type="button"
                    onClick={(event) => {
                      event.stopPropagation();
                      event.preventDefault();
                      handleClearFile();
                    }}
                    className="absolute right-2 top-2 z-10 inline-flex h-7 w-7 items-center justify-center rounded-full bg-black/60 text-white transition-colors hover:bg-black/80"
                    aria-label="Remove selected image"
                  >
                    <X size={14} />
                  </button>
                  <Image
                    src={preview}
                    alt="CCCD preview"
                    width={900}
                    height={700}
                    unoptimized
                    className="h-64 w-full rounded-xl object-cover"
                  />
                </div>
              ) : (
                <div className="flex h-64 flex-col items-center justify-center gap-2 rounded-xl bg-slate-50 text-slate-500">
                  <UploadCloud size={28} />
                  <p className="text-sm font-medium text-slate-700">Drop image here or click to upload</p>
                  <p className="text-xs text-slate-500">JPG/PNG, up to 12MB</p>
                </div>
              )}
            </div>

            {file ? <p className="truncate text-xs text-slate-500">{file.name}</p> : null}

            <div className="flex flex-wrap items-center gap-3">
              <button
                type="button"
                className="glass-button-primary"
                disabled={!canSubmit}
                onClick={handleProcess}
              >
                {loading ? <LoaderCircle size={16} className="animate-spin" /> : <FileUp size={16} />}
                Process OCR
              </button>
              <span className="text-xs text-slate-500">
                Endpoint: {process.env.NEXT_PUBLIC_KYC_PYTHON_SERVICE_URL || "http://localhost:8001/process"}
              </span>
            </div>
          </div>

          {errorMessage ? (
            <p className="mt-4 rounded-xl border border-rose-200 bg-rose-50 px-3 py-2 text-sm text-rose-600">
              {errorMessage}
            </p>
          ) : null}
        </section>

        {result ? (
          <section className="glass-panel space-y-5">
            <h2 className="text-xl font-semibold text-slate-900">OCR Result</h2>

            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              <div className="rounded-2xl border border-white/70 bg-white/75 p-4">
                <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Confidence</p>
                <p className="mt-2 text-lg font-semibold text-slate-900">{result.confidence_score}</p>
              </div>
              <div className="rounded-2xl border border-white/70 bg-white/75 p-4">
                <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Line Count</p>
                <p className="mt-2 text-lg font-semibold text-slate-900">{result.processing_meta.line_count}</p>
              </div>
              <div className="rounded-2xl border border-white/70 bg-white/75 p-4">
                <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Card Detected</p>
                <p className="mt-2 text-lg font-semibold text-slate-900">
                  {result.processing_meta.card_detected ? "Yes" : "No"}
                </p>
              </div>
              <div className="rounded-2xl border border-white/70 bg-white/75 p-4">
                <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Processing Time</p>
                <p className="mt-2 text-lg font-semibold text-slate-900">
                  {result.processing_meta.processing_time_ms} ms
                </p>
              </div>
            </div>

            <div className="grid gap-3 sm:grid-cols-2">
              <div className="rounded-2xl border border-white/70 bg-white/75 p-4">
                <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Full Name</p>
                <p className="mt-2 text-sm text-slate-800">{result.extracted_data.fullName || "-"}</p>
              </div>
              <div className="rounded-2xl border border-white/70 bg-white/75 p-4">
                <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">ID Number</p>
                <p className="mt-2 text-sm text-slate-800">{result.extracted_data.idNumber || "-"}</p>
              </div>
              <div className="rounded-2xl border border-white/70 bg-white/75 p-4">
                <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Date of Birth</p>
                <p className="mt-2 text-sm text-slate-800">{result.extracted_data.dateOfBirth || "-"}</p>
              </div>
              <div className="rounded-2xl border border-white/70 bg-white/75 p-4">
                <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Place of Origin</p>
                <p className="mt-2 text-sm text-slate-800">{result.extracted_data.placeOfOrigin || "-"}</p>
              </div>
            </div>

            <div className="rounded-2xl border border-white/70 bg-white/75 p-4">
              <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Permanent Address</p>
              <p className="mt-2 text-sm text-slate-800">{result.extracted_data.permanentAddress || "-"}</p>
            </div>

            <div className="rounded-2xl border border-white/70 bg-white/75 p-4">
              <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Raw Text</p>
              <pre className="mt-2 whitespace-pre-wrap break-words text-sm text-slate-700">
                {result.raw_text || "-"}
              </pre>
            </div>
          </section>
        ) : null}
      </div>
    </Layout>
  );
}

import { useEffect, useMemo, useRef, useState } from "react";
import type { DragEvent, RefObject } from "react";
import { useRouter } from "next/router";
import Image from "next/image";
import {
  AlertTriangle,
  CheckCircle2,
  FileUp,
  IdCard,
  LoaderCircle,
  ShieldCheck,
  UploadCloud,
  X,
} from "lucide-react";
import Layout from "@/components/Layout";
import KycStatusBadge from "@/components/KycStatusBadge";
import { useAuth } from "@/contexts/AuthContext";
import { ApiError } from "@/services/apiClient";
import { userService } from "@/services/userService";
import type { User } from "@/types/user";

const MAX_FILE_SIZE = 5 * 1024 * 1024;
const ACCEPTED_TYPES = ["image/jpeg", "image/png"];

type DocumentSide = "front" | "back";

function getErrorMessage(error: unknown) {
  if (error instanceof ApiError) {
    return error.message;
  }
  if (error instanceof Error) {
    return error.message;
  }
  return "Unable to process KYC action right now.";
}

function validateFile(file: File) {
  if (!ACCEPTED_TYPES.includes(file.type)) {
    return "Only JPG and PNG images are supported.";
  }

  if (file.size > MAX_FILE_SIZE) {
    return "File size must be 5MB or less.";
  }

  return null;
}

interface UploadBoxProps {
  title: string;
  file: File | null;
  preview: string | null;
  inputRef: RefObject<HTMLInputElement | null>;
  onSelectFile: (file: File) => void;
  onClearFile: () => void;
}

function UploadBox({ title, file, preview, inputRef, onSelectFile, onClearFile }: UploadBoxProps) {
  const handleDrop = (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    const droppedFile = event.dataTransfer.files?.[0];
    if (droppedFile) {
      onSelectFile(droppedFile);
    }
  };

  return (
    <div>
      <p className="mb-2 text-sm font-semibold text-slate-700">{title}</p>
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
        className="group cursor-pointer rounded-2xl border border-dashed border-slate-300 bg-white/70 p-4 transition-colors hover:border-slate-500 hover:bg-white"
      >
        <input
          ref={inputRef}
          type="file"
          accept=".jpg,.jpeg,.png,image/jpeg,image/png"
          className="hidden"
          onChange={(event) => {
            const selectedFile = event.target.files?.[0];
            if (selectedFile) {
              onSelectFile(selectedFile);
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
                onClearFile();
              }}
              className="absolute right-2 top-2 z-10 inline-flex h-7 w-7 items-center justify-center rounded-full bg-black/60 text-white transition-colors hover:bg-black/80"
              aria-label={`Remove ${title} image`}
            >
              <X size={14} />
            </button>
            <Image
              src={preview}
              alt={title}
              width={900}
              height={700}
              unoptimized
              className="h-60 w-full rounded-xl object-cover"
            />
          </div>
        ) : (
          <div className="flex h-60 flex-col items-center justify-center gap-2 rounded-xl bg-slate-50 text-slate-500">
            <UploadCloud size={28} />
            <p className="text-sm font-medium text-slate-700">Drop image here or click to upload</p>
            <p className="text-xs text-slate-500">JPG/PNG, up to 5MB</p>
          </div>
        )}
      </div>
      {file ? <p className="mt-2 truncate text-xs text-slate-500">{file.name}</p> : null}
    </div>
  );
}

export default function UserKycPage() {
  const router = useRouter();
  const { user, token, isAuthLoading, refreshProfile } = useAuth();
  const [profile, setProfile] = useState<User | null>(null);
  const [pageLoading, setPageLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  const [frontFile, setFrontFile] = useState<File | null>(null);
  const [backFile, setBackFile] = useState<File | null>(null);
  const [frontPreview, setFrontPreview] = useState<string | null>(null);
  const [backPreview, setBackPreview] = useState<string | null>(null);
  const [declaredIdNumber, setDeclaredIdNumber] = useState("");

  const frontInputRef = useRef<HTMLInputElement>(null);
  const backInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (!frontFile) {
      setFrontPreview(null);
      return;
    }
    const objectUrl = URL.createObjectURL(frontFile);
    setFrontPreview(objectUrl);
    return () => URL.revokeObjectURL(objectUrl);
  }, [frontFile]);

  useEffect(() => {
    if (!backFile) {
      setBackPreview(null);
      return;
    }
    const objectUrl = URL.createObjectURL(backFile);
    setBackPreview(objectUrl);
    return () => URL.revokeObjectURL(objectUrl);
  }, [backFile]);

  useEffect(() => {
    if (isAuthLoading) {
      return;
    }

    if (!user || !token) {
      void router.replace("/");
      return;
    }

    if (user.role === "admin") {
      void router.replace("/admin/kyc-management");
      return;
    }

    const loadProfile = async () => {
      setPageLoading(true);
      setErrorMessage(null);
      try {
        const profileData = await userService.getMe(token);
        setProfile(profileData);
      } catch (error) {
        setErrorMessage(getErrorMessage(error));
      } finally {
        setPageLoading(false);
      }
    };

    void loadProfile();
  }, [isAuthLoading, router, token, user]);

  const canSubmit = useMemo(
    () => Boolean(frontFile && backFile && token && !submitting),
    [backFile, frontFile, submitting, token]
  );

  const handleSelectFile = (side: DocumentSide, file: File) => {
    const validationError = validateFile(file);
    if (validationError) {
      setErrorMessage(validationError);
      return;
    }

    setErrorMessage(null);
    setSuccessMessage(null);

    if (side === "front") {
      setFrontFile(file);
      return;
    }
    setBackFile(file);
  };

  const handleSubmit = async () => {
    if (!token || !frontFile || !backFile) {
      setErrorMessage("Please upload both front and back images before submitting.");
      return;
    }

    setSubmitting(true);
    setErrorMessage(null);
    setSuccessMessage(null);

    try {
      const response = await userService.submitKycDocuments(
        token,
        frontFile,
        backFile,
        declaredIdNumber
      );
      const refreshed = await userService.getMe(token);
      setProfile(refreshed);
      setSuccessMessage(response.message || "KYC submission completed successfully.");
      setFrontFile(null);
      setBackFile(null);
      setDeclaredIdNumber("");
      await refreshProfile();
    } catch (error) {
      setErrorMessage(getErrorMessage(error));
    } finally {
      setSubmitting(false);
    }
  };

  const handleClearFile = (side: DocumentSide) => {
    setErrorMessage(null);
    setSuccessMessage(null);

    if (side === "front") {
      setFrontFile(null);
      if (frontInputRef.current) {
        frontInputRef.current.value = "";
      }
      return;
    }

    setBackFile(null);
    if (backInputRef.current) {
      backInputRef.current.value = "";
    }
  };

  if (isAuthLoading || pageLoading) {
    return (
      <Layout>
        <div className="glass-panel flex items-center justify-center gap-2 py-12 text-slate-600">
          <LoaderCircle size={18} className="animate-spin" />
          Loading KYC profile...
        </div>
      </Layout>
    );
  }

  if (!profile) {
    return (
      <Layout>
        <div className="glass-panel text-center">
          <h1 className="text-xl font-semibold text-slate-900">KYC Profile Unavailable</h1>
          <p className="mt-2 text-sm text-slate-600">
            {errorMessage || "We could not load your KYC data. Please try again."}
          </p>
        </div>
      </Layout>
    );
  }

  return (
    <Layout>
      <div className="space-y-6">
        <section className="glass-panel">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <p className="text-sm font-medium text-slate-500">Profile Verification</p>
              <h1 className="text-3xl font-semibold text-slate-900">My KYC Submission</h1>
            </div>
            <KycStatusBadge status={profile.kycStatus} />
          </div>

          <div className="mt-5 grid gap-3 sm:grid-cols-3">
            <div className="rounded-2xl border border-white/70 bg-white/75 p-4">
              <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Current Status</p>
              <p className="mt-2 text-lg font-semibold text-slate-900">{profile.kycStatus || "pending"}</p>
            </div>
            <div className="rounded-2xl border border-white/70 bg-white/75 p-4">
              <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Verification</p>
              <p className="mt-2 inline-flex items-center gap-2 text-lg font-semibold text-slate-900">
                {profile.isVerified ? (
                  <>
                    <CheckCircle2 size={16} className="text-emerald-600" />
                    Verified
                  </>
                ) : (
                  <>
                    <AlertTriangle size={16} className="text-amber-500" />
                    Not Verified
                  </>
                )}
              </p>
            </div>
            <div className="rounded-2xl border border-white/70 bg-white/75 p-4">
              <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Account Role</p>
              <p className="mt-2 text-lg font-semibold text-slate-900">{profile.role}</p>
            </div>
          </div>

          {profile.kycRejectionReason ? (
            <div className="mt-4 rounded-2xl border border-rose-200 bg-rose-50 p-4 text-sm text-rose-700">
              <p className="font-semibold">Latest Rejection Reason</p>
              <p className="mt-1">{profile.kycRejectionReason}</p>
            </div>
          ) : null}
        </section>

        <section className="glass-panel">
          <h2 className="text-xl font-semibold text-slate-900">Submit CCCD Documents</h2>
          <p className="mt-2 text-sm text-slate-600">
            Upload clear photos of your CCCD front and back side. Accepted formats: JPG, PNG. Maximum size
            5MB per file. Ensure all text is readable and corners are visible.
          </p>

          <div className="mt-5 grid gap-4 md:grid-cols-2">
            <UploadBox
              title="CCCD Front"
              file={frontFile}
              preview={frontPreview}
              inputRef={frontInputRef}
              onSelectFile={(file) => handleSelectFile("front", file)}
              onClearFile={() => handleClearFile("front")}
            />
            <UploadBox
              title="CCCD Back"
              file={backFile}
              preview={backPreview}
              inputRef={backInputRef}
              onSelectFile={(file) => handleSelectFile("back", file)}
              onClearFile={() => handleClearFile("back")}
            />
          </div>

          <label className="mt-4 flex flex-col gap-1">
            <span className="text-xs font-semibold uppercase tracking-wide text-slate-500">
              Declared ID Number (Optional)
            </span>
            <span className="glass-input-wrapper">
              <IdCard size={16} className="text-slate-500" />
              <input
                type="text"
                className="glass-input"
                value={declaredIdNumber}
                onChange={(event) => setDeclaredIdNumber(event.target.value)}
                placeholder="Enter ID number to improve matching accuracy"
              />
            </span>
          </label>

          <div className="mt-5 flex flex-wrap items-center gap-3">
            <button
              type="button"
              className="glass-button-primary"
              disabled={!canSubmit}
              onClick={handleSubmit}
            >
              {submitting ? <LoaderCircle size={16} className="animate-spin" /> : <FileUp size={16} />}
              Submit for KYC
            </button>
            <span className="text-xs text-slate-500">Submission may take a few moments while OCR runs.</span>
          </div>

          {errorMessage ? (
            <p className="mt-4 rounded-xl border border-rose-200 bg-rose-50 px-3 py-2 text-sm text-rose-600">
              {errorMessage}
            </p>
          ) : null}

          {successMessage ? (
            <p className="mt-4 rounded-xl border border-emerald-200 bg-emerald-50 px-3 py-2 text-sm text-emerald-700">
              {successMessage}
            </p>
          ) : null}
        </section>

        <section className="glass-panel">
          <h2 className="inline-flex items-center gap-2 text-xl font-semibold text-slate-900">
            <ShieldCheck size={18} />
            Uploaded KYC Documents
          </h2>

          {profile.kycDocuments?.length ? (
            <div className="mt-4 grid gap-3 sm:grid-cols-2">
              {profile.kycDocuments.map((documentUrl, index) => (
                <a
                  key={`${documentUrl}-${index}`}
                  href={documentUrl}
                  target="_blank"
                  rel="noreferrer"
                  className="group overflow-hidden rounded-2xl border border-white/70 bg-white/75"
                >
                  <Image
                    src={documentUrl}
                    alt={`KYC document ${index + 1}`}
                    width={900}
                    height={700}
                    unoptimized
                    className="h-52 w-full object-cover transition-transform duration-300 group-hover:scale-105"
                  />
                </a>
              ))}
            </div>
          ) : (
            <p className="mt-3 text-sm text-slate-600">No KYC documents uploaded yet.</p>
          )}
        </section>
      </div>
    </Layout>
  );
}

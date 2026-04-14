import type { Blob } from "./crypto-client";

const DRIVE_API = "https://www.googleapis.com/drive/v3";
const DRIVE_UPLOAD = "https://www.googleapis.com/upload/drive/v3";
const BLOB_NAME = "passport.json";

export interface DriveFile {
  id: string;
  name: string;
}

export async function findBlobFile(accessToken: string): Promise<DriveFile | null> {
  const params = new URLSearchParams({
    spaces: "appDataFolder",
    fields: "files(id,name)",
    q: `name = '${BLOB_NAME}'`,
    pageSize: "1",
  });
  const res = await fetch(`${DRIVE_API}/files?${params}`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!res.ok) throw new Error(`drive list failed: ${res.status}`);
  const data = (await res.json()) as { files?: DriveFile[] };
  return data.files?.[0] ?? null;
}

export async function downloadBlob(accessToken: string, fileId: string): Promise<Blob> {
  const res = await fetch(`${DRIVE_API}/files/${fileId}?alt=media`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!res.ok) throw new Error(`drive download failed: ${res.status}`);
  return (await res.json()) as Blob;
}

export async function uploadBlob(accessToken: string, blob: Blob): Promise<DriveFile> {
  const boundary = `----passport${crypto.getRandomValues(new Uint32Array(1))[0].toString(16)}`;
  const metadata = { name: BLOB_NAME, parents: ["appDataFolder"], mimeType: "application/json" };
  const body =
    `--${boundary}\r\n` +
    `Content-Type: application/json; charset=UTF-8\r\n\r\n` +
    `${JSON.stringify(metadata)}\r\n` +
    `--${boundary}\r\n` +
    `Content-Type: application/json\r\n\r\n` +
    `${JSON.stringify(blob)}\r\n` +
    `--${boundary}--`;

  const res = await fetch(`${DRIVE_UPLOAD}/files?uploadType=multipart&fields=id,name`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": `multipart/related; boundary=${boundary}`,
    },
    body,
  });
  if (!res.ok) throw new Error(`drive upload failed: ${res.status} ${await res.text()}`);
  return (await res.json()) as DriveFile;
}

import type { Blob } from "./crypto-client";

const DRIVE_API = "https://www.googleapis.com/drive/v3";
const DRIVE_UPLOAD = "https://www.googleapis.com/upload/drive/v3";
const BLOB_NAME = "passport.json";
const VISIBLE_FOLDER_NAME = "Pubky Passport";
const VISIBLE_BACKUP_NAME = "Pubky Passport Encrypted Backup.json";

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

export async function deleteBlob(accessToken: string, fileId: string): Promise<void> {
  const res = await fetch(`${DRIVE_API}/files/${fileId}`, {
    method: "DELETE",
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!res.ok && res.status !== 404) {
    throw new Error(`drive delete failed: ${res.status}`);
  }
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

function driveString(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/'/g, "\\'");
}

async function findVisibleFolder(accessToken: string): Promise<DriveFile | null> {
  const params = new URLSearchParams({
    spaces: "drive",
    fields: "files(id,name)",
    q: [
      `name = '${driveString(VISIBLE_FOLDER_NAME)}'`,
      "mimeType = 'application/vnd.google-apps.folder'",
      "trashed = false",
    ].join(" and "),
    pageSize: "1",
  });
  const res = await fetch(`${DRIVE_API}/files?${params}`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!res.ok) throw new Error(`drive folder list failed: ${res.status}`);
  const data = (await res.json()) as { files?: DriveFile[] };
  return data.files?.[0] ?? null;
}

async function createVisibleFolder(accessToken: string): Promise<DriveFile> {
  const res = await fetch(`${DRIVE_API}/files?fields=id,name`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      name: VISIBLE_FOLDER_NAME,
      mimeType: "application/vnd.google-apps.folder",
    }),
  });
  if (!res.ok) throw new Error(`drive folder create failed: ${res.status} ${await res.text()}`);
  return (await res.json()) as DriveFile;
}

async function findVisibleBackup(accessToken: string, folderId: string): Promise<DriveFile | null> {
  const params = new URLSearchParams({
    spaces: "drive",
    fields: "files(id,name)",
    q: [
      `name = '${driveString(VISIBLE_BACKUP_NAME)}'`,
      `'${driveString(folderId)}' in parents`,
      "trashed = false",
    ].join(" and "),
    pageSize: "1",
  });
  const res = await fetch(`${DRIVE_API}/files?${params}`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!res.ok) throw new Error(`drive backup list failed: ${res.status}`);
  const data = (await res.json()) as { files?: DriveFile[] };
  return data.files?.[0] ?? null;
}

async function uploadVisibleBackup(
  accessToken: string,
  folderId: string,
  blob: Blob,
): Promise<DriveFile> {
  const boundary = `----passport${crypto.getRandomValues(new Uint32Array(1))[0].toString(16)}`;
  const metadata = {
    name: VISIBLE_BACKUP_NAME,
    parents: [folderId],
    mimeType: "application/json",
  };
  const body =
    `--${boundary}\r\n` +
    `Content-Type: application/json; charset=UTF-8\r\n\r\n` +
    `${JSON.stringify(metadata)}\r\n` +
    `--${boundary}\r\n` +
    `Content-Type: application/json\r\n\r\n` +
    `${JSON.stringify(blob, null, 2)}\r\n` +
    `--${boundary}--`;

  const res = await fetch(`${DRIVE_UPLOAD}/files?uploadType=multipart&fields=id,name`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": `multipart/related; boundary=${boundary}`,
    },
    body,
  });
  if (!res.ok) throw new Error(`drive visible backup upload failed: ${res.status} ${await res.text()}`);
  return (await res.json()) as DriveFile;
}

async function updateVisibleBackup(
  accessToken: string,
  fileId: string,
  blob: Blob,
): Promise<DriveFile> {
  const res = await fetch(`${DRIVE_UPLOAD}/files/${fileId}?uploadType=media&fields=id,name`, {
    method: "PATCH",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(blob, null, 2),
  });
  if (!res.ok) throw new Error(`drive visible backup update failed: ${res.status} ${await res.text()}`);
  return (await res.json()) as DriveFile;
}

export async function saveVisibleBackup(accessToken: string, blob: Blob): Promise<DriveFile> {
  const folder = (await findVisibleFolder(accessToken)) ?? (await createVisibleFolder(accessToken));
  const existing = await findVisibleBackup(accessToken, folder.id);
  return existing
    ? updateVisibleBackup(accessToken, existing.id, blob)
    : uploadVisibleBackup(accessToken, folder.id, blob);
}

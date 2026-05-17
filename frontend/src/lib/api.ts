const API_BASE = import.meta.env.VITE_API_BASE_URL ?? '';

export async function apiGet<T>(path: string): Promise<T> {
  const token = localStorage.getItem('accessToken');
  const response = await fetch(`${API_BASE}${path}`, {
    headers: token ? { authorization: `Bearer ${token}` } : {}
  });
  if (!response.ok) throw new Error(await response.text());
  return response.json() as Promise<T>;
}

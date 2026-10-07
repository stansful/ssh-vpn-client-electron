/**
 * Hand-off for "Add a new key" started outside the server form (a
 * `new-key` intent with `returnTo: "server-form"`): the keys page saves the
 * key, remembers its id here and opens a new server form, which picks it.
 */
let pendingKeyId: string | undefined;

export function rememberKeyForServerForm(id: string): void {
  pendingKeyId = id;
}

/** Returns the remembered key once, then forgets it. */
export function takeKeyForServerForm(): string | undefined {
  const id = pendingKeyId;
  pendingKeyId = undefined;
  return id;
}

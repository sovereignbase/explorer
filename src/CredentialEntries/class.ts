import { CipherKey } from '@sovereignbase/cryptosuite'

export type CredentialEntry = Readonly<
  [id: string, path: string, cipherKey: CipherKey, dateModified: string]
>

export class CredentialEntries {}

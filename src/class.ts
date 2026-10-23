import { type CipherKey } from '@sovereignbase/cryptosuite'
import { loadObject, type URLString } from '@sovereignbase/storage'
export class Explorer {
  constructor(public storageURL: URLString) {}
  async loadObjectById<T>(
    id: string,
    cipherKey: CipherKey
  ): Promise<T | undefined> {
    return (await loadObject(this.storageURL + id, cipherKey, false)) as T
  }
}

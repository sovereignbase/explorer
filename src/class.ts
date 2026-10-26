import { Cryptographic, type CipherKey } from '@sovereignbase/cryptosuite'
import { loadObject, storeObject, type URLString } from '@sovereignbase/storage'
import { unknownError } from './.errors/unkown.js'
import type {
  ExplorerEventMap,
  AuthenticationResult,
  ExplorerEventListenerFor,
} from './.types/type.js'
import { RecentEntries } from './RecentEntries/class.js'
import { Bytes } from '@sovereignbase/bytecodec'
import {
  deriveDeviceEntropy,
  type DeviceBindingStorage,
} from '@sovereignbase/hardware-bound'

export class Explorer {
  public static databaseID: string
  public static isAuthenticated: boolean
  //
  private static storageURL: URLString
  private static eventTarget?: EventTarget
  private static databaseSecret: Readonly<Uint8Array>

  public static readonly cipherKeyCache: Map<string, CipherKey> = new Map()

  /**
   * Uses a humans physical capability to resolve their virtual capability
   * @param dataPin
   * @param storage
   */
  public static async authenticate(
    dataPin: string,
    storageURL: URLString,
    bindingStorage?: DeviceBindingStorage
  ): Promise<AuthenticationResult> {
    this.storageURL = storageURL
    //
    const deviceEntropy = await deriveDeviceEntropy()
    if (!deviceEntropy) return 'authenticator-error'

    const dataPinBytes = Bytes.utf8.decode(dataPin)
    //
    const credentialSecret = await Bytes.derive(deviceEntropy, dataPinBytes, 32)
    const credentialID = await Cryptographic.identifier.derive(
      credentialSecret,
      { encoding: 'utf8', value: '@sovereignbase/explorer:credentialID' },
      32
    )
    const credentialCipherKey = await Cryptographic.cipherMessage.deriveKey(
      credentialSecret,
      Bytes.utf8.decode('@sovereignbase/explorer:credentialCipherKey')
    )
    //
    let virtualEntropy: Uint8Array
    ////////
    // SETUP
    if (typeof bindingStorage === 'string') {
      virtualEntropy = Bytes.generate(128)

      void (await this.storeObjectByID(
        credentialID,
        virtualEntropy,
        credentialCipherKey
      ))
    }
    ////////
    // LOGIN
    else {
      const result = await this.loadObjectByID(
        credentialID,
        credentialCipherKey
      )
      if (!(result instanceof Uint8Array) || result.byteLength !== 128)
        return 'invalid-data-pin'

      virtualEntropy = result
    }

    this.databaseSecret = await Bytes.derive(virtualEntropy, dataPinBytes, 128)

    this.databaseID = await Cryptographic.identifier.derive(
      this.databaseSecret,
      { encoding: 'utf8', value: '@sovereignbase/explorer:databaseID' },
      32
    )

    this.isAuthenticated = true

    return 'authenticated'
  }

  public static async loadObjectByID<T>(
    id: string,
    cipherKey: CipherKey,
    onNetworkResponse?: (data: unknown) => void | Promise<void>
  ): Promise<T | undefined> {
    if (!this.cipherKeyCache.has(id))
      void this.cipherKeyCache.set(id, cipherKey)
    //
    return (await loadObject(
      (this.storageURL + id) as URLString,
      cipherKey,
      false,
      onNetworkResponse
    )) as T
  }

  public static async storeObjectByID<T>(
    id: string,
    object: T,
    cipherKey: CipherKey
  ) {
    if (!this.cipherKeyCache.has(id))
      void this.cipherKeyCache.set(id, cipherKey)
    //
    return void storeObject(
      (this.storageURL + id) as URLString,
      object,
      cipherKey
    )
  }

  public static async get recentEntries(): RecentEntries {
    if (this._recentEntries) return this._recentEntries
    const salt = Bytes.utf8.decode('@sovereignbase/explorer:recentEntries')
    const recentEntriesID = await Cryptographic.identifier.derive(
      {
        value: this.databaseID,
        encoding: 'base64url',
      },
      salt,
      32
    )
    const recentEntriesCipherKey = await Cryptographic.cipherMessage.deriveKey(
      this.databaseSecret,
      salt
    )

    this.cipherKeyCache.set(recentEntriesID, recentEntriesCipherKey)
  }
  private static _recentEntries: RecentEntries

  /**
   * Registers a callback or listener object for a typed document event.
   * @param type The event name.
   * @param listener The listener to register; `null` is ignored.
   * @param options A capture flag or options such as `once` and `signal`.
   */
  public static addEventListener<K extends keyof ExplorerEventMap>(
    type: K,
    listener: ExplorerEventListenerFor<K> | null,
    options?: boolean | AddEventListenerOptions
  ): void {
    try {
      void (this.eventTarget ??= new EventTarget()).addEventListener(
        type,
        listener as EventListenerOrEventListenerObject | null,
        options
      )
    } catch (cause) {
      throw unknownError(cause, 'Explorer.addEventListener()')
    }
  }

  /**
   * Removes a listener with the matching event name, identity and capture flag.
   * @param type The event name.
   * @param listener The previously registered listener.
   * @param options The capture flag, directly or within listener options.
   */
  public static removeEventListener<K extends keyof ExplorerEventMap>(
    type: K,
    listener: ExplorerEventListenerFor<K> | null,
    options?: boolean | EventListenerOptions
  ): void {
    try {
      void this.eventTarget?.removeEventListener(
        type,
        listener as EventListenerOrEventListenerObject | null,
        options
      )
    } catch (cause) {
      throw unknownError(cause, 'Explorer.removeEventListener()')
    }
  }

  /**
   * Synchronously dispatches a typed `CustomEvent` to registered listeners.
   * @param type The event name.
   * @param detail The value exposed as `event.detail`.
   */
  public static dispatchEvent<K extends keyof ExplorerEventMap>(
    type: K,
    detail: ExplorerEventMap[K]
  ): void {
    try {
      void this.eventTarget?.dispatchEvent(new CustomEvent(type, { detail }))
    } catch (cause) {
      throw unknownError(cause, 'Explorer.dispatchEvent()')
    }
  }
}

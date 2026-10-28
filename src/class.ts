import { Cryptographic, type CipherKey } from '@sovereignbase/cryptosuite'
import {
  deleteObject,
  loadObject,
  storeObject,
  type URLString,
} from '@sovereignbase/storage'
import { unknownError } from './.errors/unkown.js'
import type {
  AuthenticationResult,
  AuthenticationSetupParams,
  //
  ExplorerEventMap,
  ExplorerEventListenerFor,
  //
  ExplorerDelta,
} from './.types/type.js'
import { RecentEntries, RecentEntry } from './RecentEntries/class.js'
import {
  CredentialEntries,
  CredentialEntry,
  type CredentialEvent,
} from './CredentialEntries/class.js'
import { Bytes } from '@sovereignbase/bytecodec'
import { deriveDeviceEntropy } from '@sovereignbase/hardware-bound'
import { isRecord } from '@sovereignbase/utils'
import { readableUserAgent } from '@sovereignbase/dom-utils'
import { SequencedArrayChange } from '@sovereignbase/sequenced'

export class Explorer {
  public static databaseID: string
  public static isAuthenticated: boolean
  //
  private static storageURL: URLString
  private static eventTarget?: EventTarget
  private static databaseSecret: Readonly<Uint8Array>
  private static sessionCredential?: CredentialEvent = {}

  public static readonly cipherKeyCache: Map<string, CipherKey> = new Map()

  /**
   * Uses a humans physical capability to resolve their virtual capability
   * @param dataPin
   * @param storage
   */
  public static async authenticate(
    dataPin: string,
    storageURL: URLString,
    setupParams?: AuthenticationSetupParams
  ): Promise<AuthenticationResult> {
    this.storageURL = storageURL
    //
    const deviceEntropy = await deriveDeviceEntropy()
    if (!deviceEntropy) return 'authenticator-error'
    //
    this.sessionCredential = {
      timestamp: Date.now(),
      userAgent: readableUserAgent(),
    }
    //
    const dataPinBytes = Bytes.utf8.decode(dataPin)
    //
    const credentialSecret = await Bytes.derive(deviceEntropy, dataPinBytes, 32)
    //
    const credentialID = await Cryptographic.identifier.derive(
      credentialSecret,
      Bytes.utf8.decode('@sovereignbase/exploreCredentialID'),
      32
    )
    this.sessionCredential.id = credentialID
    //
    const credentialCipherKey = await Cryptographic.cipherMessage.deriveKey(
      credentialSecret,
      Bytes.utf8.decode('@sovereignbase/explorer:CredentialCipherKey')
    )
    //
    let virtualEntropy: Uint8Array
    ////////
    // SETUP
    if (isRecord(setupParams)) {
      virtualEntropy = Bytes.generate(64)

      void (await this.storeObjectByID(
        credentialID,
        virtualEntropy,
        credentialCipherKey
      ))

      this.sessionCredential.name = setupParams.credentialName
      this.sessionCredential.entropy = deviceEntropy
      this.sessionCredential.storage = setupParams.bindingStorage
    }
    ////////
    // LOGIN
    else {
      const result = await this.loadObjectByID(
        credentialID,
        credentialCipherKey
      )
      if (!(result instanceof Uint8Array) || result.byteLength !== 64)
        return 'invalid-data-pin'

      virtualEntropy = result
    }
    //
    this.databaseSecret = await Bytes.derive(virtualEntropy, dataPinBytes, 64)

    this.databaseID = await Cryptographic.identifier.derive(
      this.databaseSecret,
      Bytes.utf8.decode('@sovereignbase/explorer:DatabaseID'),
      32
    )

    this.isAuthenticated = true

    void (await this.loadCredentialEntries()).record(this.sessionCredential)
    delete this.sessionCredential

    return 'authenticated'
  }

  public static async listCredentialEntries(
    onChange?: (splice: SequencedArrayChange<CredentialEntry>) => void
  ): Promise<
    [
      cleanup: () => void,
      entries: ReadonlyArray<Readonly<CredentialEntry>>,
      sessionCredentialID: string,
    ]
  > {
    const credentialEntries = await this.loadCredentialEntries()

    const listener = onChange
      ? ({ detail }: CustomEvent<SequencedArrayChange<CredentialEntry>>) =>
          onChange(detail)
      : undefined

    if (listener) credentialEntries.addEventListener('change', listener)

    return [
      () => {
        if (listener) credentialEntries.removeEventListener('change', listener)
      },
      credentialEntries.list(),
      credentialEntries.sessionCredentialID,
    ]
  }

  public static async listRecentEntries(
    onChange?: (splice: SequencedArrayChange<RecentEntry>) => void
  ): Promise<
    [cleanup: () => void, entries: ReadonlyArray<Readonly<RecentEntry>>]
  > {
    const recentEntries = await this.loadRecentEntries()

    const listener = onChange
      ? ({ detail }: CustomEvent<SequencedArrayChange<RecentEntry>>) =>
          onChange(detail)
      : undefined

    if (listener) recentEntries.addEventListener('change', listener)

    return [
      () => {
        if (listener) recentEntries.removeEventListener('change', listener)
      },
      recentEntries.values(),
    ]
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
  ): Promise<void> {
    if (!this.cipherKeyCache.has(id))
      void this.cipherKeyCache.set(id, cipherKey)
    //
    return void (await storeObject(
      (this.storageURL + id) as URLString,
      object,
      cipherKey
    ))
  }

  public static async deleteObjectByID(id: string): Promise<void> {
    return void (await deleteObject((this.storageURL + id) as URLString))
  }

  public static apply(data: unknown): void {
    return void queueMicrotask(async () => {
      if (!this.isExplorerDelta(data)) return
      switch (data[0]) {
        case 'recentEntries': {
          void (await this.loadRecentEntries()).apply(data[1])
          break
        }
        case 'credentialEntries': {
          void (await this.loadCredentialEntries()).apply(data[1])
          break
        }
      }
      return
    })
  }

  //* ███████╗██╗   ██╗███████╗███╗   ██╗████████╗   ████████╗ █████╗ ██████╗  ██████╗ ███████╗████████╗
  //* ██╔════╝██║   ██║██╔════╝████╗  ██║╚══██╔══╝   ╚══██╔══╝██╔══██╗██╔══██╗██╔════╝ ██╔════╝╚══██╔══╝
  //* █████╗  ██║   ██║█████╗  ██╔██╗ ██║   ██║         ██║   ███████║██████╔╝██║  ███╗█████╗     ██║
  //* ██╔══╝  ╚██╗ ██╔╝██╔══╝  ██║╚██╗██║   ██║         ██║   ██╔══██║██╔══██╗██║   ██║██╔══╝     ██║
  //* ███████╗ ╚████╔╝ ███████╗██║ ╚████║   ██║         ██║   ██║  ██║██║  ██║╚██████╔╝███████╗   ██║
  //* ╚══════╝  ╚═══╝  ╚══════╝╚═╝  ╚═══╝   ╚═╝         ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝

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

  //* ██╗  ██╗███████╗██╗     ██████╗ ███████╗██████╗ ███████╗
  //* ██║  ██║██╔════╝██║     ██╔══██╗██╔════╝██╔══██╗██╔════╝
  //* ███████║█████╗  ██║     ██████╔╝█████╗  ██████╔╝███████╗
  //* ██╔══██║██╔══╝  ██║     ██╔═══╝ ██╔══╝  ██╔══██╗╚════██║
  //* ██║  ██║███████╗███████╗██║     ███████╗██║  ██║███████║
  //* ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝     ╚══════╝╚═╝  ╚═╝╚══════╝

  private static isExplorerDelta(data: unknown): data is ExplorerDelta {
    return Array.isArray(data) && typeof data[0] === 'string'
  }

  private static recentEntries?: RecentEntries

  private static async loadRecentEntries(): Promise<RecentEntries> {
    if (!this.isAuthenticated) throw new Error()
    if (this.recentEntries) return this.recentEntries

    const id = await Cryptographic.identifier.derive(
      this.databaseSecret,
      Bytes.utf8.decode('@sovereignbase/explorer:RecentEntriesID'),
      32
    )
    const ck = await Cryptographic.cipherMessage.deriveKey(
      this.databaseSecret,
      Bytes.utf8.decode('@sovereignbase/explorer:RecentEntriesCipherKey')
    )

    const trustedSnapshot = await this.loadObjectByID(
      id,
      ck,
      (snapshot) => void this.recentEntries!.merge(snapshot)
    )

    this.recentEntries = new RecentEntries(id, ck, 0, trustedSnapshot)

    return this.recentEntries
  }

  private static credentialEntries?: CredentialEntries

  private static async loadCredentialEntries(): Promise<CredentialEntries> {
    if (!this.isAuthenticated) throw new Error()
    if (this.credentialEntries) return this.credentialEntries

    const id = await Cryptographic.identifier.derive(
      this.databaseSecret,
      Bytes.utf8.decode('@sovereignbase/explorer:CredentialEntriesID'),
      32
    )
    const ck = await Cryptographic.cipherMessage.deriveKey(
      this.databaseSecret,
      Bytes.utf8.decode('@sovereignbase/explorer:CredentialEntriesCipherKey')
    )

    const trustedSnapshot = await this.loadObjectByID(
      id,
      ck,
      (snapshot) => void this.credentialEntries!.merge(snapshot)
    )

    this.credentialEntries = new CredentialEntries(
      id,
      ck,
      this.sessionCredential!.id!,
      0,
      trustedSnapshot
    )

    return this.credentialEntries
  }
}

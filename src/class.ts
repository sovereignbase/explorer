import {
  deleteObject,
  loadObject,
  storeObject,
  type URLString,
} from '@sovereignbase/storage'
import { isRecord, type DeepReadonly } from '@sovereignbase/utils'
import { Bytes } from '@sovereignbase/bytecodec'
import { readableUserAgent } from '@sovereignbase/dom-utils'
import { deriveDeviceEntropy } from '@sovereignbase/hardware-bound'
import { Cryptographic, type CipherKey } from '@sovereignbase/cryptosuite'
//
import type {
  AuthenticationResult,
  AuthenticationSetupParams,
  //
  ExplorerEventMap,
  ExplorerEventListenerFor,
  //
  ExplorerDelta,
} from './.types/type.js'
//
import { ExplorerError } from './.errors/class.js'
import { unknownError } from './.errors/unkown.js'
//
import {
  CredentialEntries,
  type CredentialEntry,
  type CredentialEvent,
  type CredentialEntriesChange,
} from './CredentialEntries/class.js'
//
import {
  RecentEntries,
  type RecentEntry,
  type RecentEntriesChange,
} from './RecentEntries/class.js'

/**
 * Provides authentication, encrypted object storage, and access to
 * the database's synchronized entries.
 *
 * Maintains the authenticated database context and exposes static methods
 * for managing stored objects, observing entries, and applying remote deltas.
 */
export class Explorer {
  /** The identifier of the authenticated database. */
  public static databaseID: string

  /** Indicates whether the database has been authenticated. */
  public static isAuthenticated: boolean

  //
  private static storageURL: URLString
  private static eventTarget?: EventTarget
  private static databaseSecret: Readonly<Uint8Array>
  private static sessionCredential?: CredentialEvent = {}

  /**
   * Caches cipher keys by object identifier.
   *
   * Existing entries are preserved when an object is accessed with
   * a cipher key.
   */
  public static readonly cipherKeyCache: Map<string, CipherKey> = new Map()

  /**
   * Authenticates a database using a data PIN and device-bound entropy.
   *
   * Derives the credential and database identifiers from cryptographic
   * secrets. When setup parameters are provided, creates and stores a
   * new credential. Otherwise, loads the existing credential.
   *
   * Records the authenticated credential in the database's credential list.
   *
   * @param dataPIN The PIN used to derive the credential and database secrets.
   * @param storageURL The base URL used to access persisted database objects.
   * @param setupParams Optional parameters for creating a new credential.
   * @returns The authentication result.
   */
  public static async authenticate(
    dataPIN: string,
    storageURL: URLString,
    setupParams?: AuthenticationSetupParams
  ): Promise<AuthenticationResult> {
    try {
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
      const dataPINBytes = Bytes.utf8.decode(dataPIN)
      //
      const credentialSecret = await Bytes.derive(
        deviceEntropy,
        dataPINBytes,
        32
      )
      //
      const credentialID = await Cryptographic.identifier.derive(
        credentialSecret,
        Bytes.utf8.decode('@sovereignbase/explorer:CredentialID'),
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
      this.databaseSecret = await Bytes.derive(virtualEntropy, dataPINBytes, 64)

      this.databaseID = await Cryptographic.identifier.derive(
        this.databaseSecret,
        Bytes.utf8.decode('@sovereignbase/explorer:DatabaseID'),
        32
      )

      this.isAuthenticated = true

      void (await this.loadCredentialEntries()).record(this.sessionCredential)
      delete this.sessionCredential

      return 'authenticated'
    } catch (cause) {
      throw unknownError(cause, 'Explorer.authenticate()')
    }
  }

  /**
   * Permanently revokes a credential and deletes its persisted data.
   *
   * Removes the credential from the database's registered credentials.
   *
   * @param credentialID The identifier of the credential to revoke.
   * @throws {ExplorerError} If the database is not authenticated.
   */
  public static async permanentlyDeleteCredential(
    credentialID: string
  ): Promise<void> {
    try {
      return void (await (
        await this.loadCredentialEntries()
      ).revoke(credentialID))
    } catch (cause) {
      throw unknownError(cause, 'Explorer.permanentlyDeleteCredential()')
    }
  }

  /**
   * Returns the registered credentials and optionally observes their changes.
   *
   * The returned tuple contains a cleanup function, the current credential
   * entries, and the identifier of the current session's credential.
   *
   * The cleanup function removes the registered change listener, if any.
   *
   * @param onChange An optional callback invoked when the entries change.
   * @returns The cleanup function, credential entries, and session credential ID.
   * @throws {ExplorerError} If the database is not authenticated.
   */
  public static async listCredentialEntries(
    onChange?: (splice: CredentialEntriesChange) => void
  ): Promise<
    [
      cleanup: () => void,
      entries: DeepReadonly<Array<CredentialEntry>>,
      sessionCredentialID: string,
    ]
  > {
    try {
      const credentialEntries = await this.loadCredentialEntries()

      const listener = onChange
        ? ({ detail }: CustomEvent<CredentialEntriesChange>) => onChange(detail)
        : undefined

      if (listener) credentialEntries.addEventListener('change', listener)

      return [
        () => {
          if (listener)
            credentialEntries.removeEventListener('change', listener)
        },
        credentialEntries.list(),
        credentialEntries.sessionCredentialID,
      ]
    } catch (cause) {
      throw unknownError(cause, 'Explorer.listCredentialEntries()')
    }
  }

  /**
   * Returns the recently accessed objects and optionally observes their changes.
   *
   * The returned tuple contains a cleanup function and the current recent
   * entries. The cleanup function removes the registered change listener,
   * if any.
   *
   * @param onChange An optional callback invoked when the entries change.
   * @returns The cleanup function and recent entries.
   * @throws {ExplorerError} If the database is not authenticated.
   */
  public static async listRecentEntries(
    onChange?: (splice: RecentEntriesChange) => void
  ): Promise<[cleanup: () => void, entries: DeepReadonly<Array<RecentEntry>>]> {
    try {
      const recentEntries = await this.loadRecentEntries()

      const listener = onChange
        ? ({ detail }: CustomEvent<RecentEntriesChange>) => onChange(detail)
        : undefined

      if (listener) recentEntries.addEventListener('change', listener)

      return [
        () => {
          if (listener) recentEntries.removeEventListener('change', listener)
        },
        recentEntries.list(),
      ]
    } catch (cause) {
      throw unknownError(cause, 'Explorer.listRecentEntries()')
    }
  }

  /**
   * Loads an encrypted object using its identifier and cipher key.
   *
   * Caches the cipher key if the identifier has not been encountered before.
   *
   * @typeParam T The expected type of the loaded object.
   * @param id The identifier of the object to load.
   * @param cipherKey The key used to decrypt the object.
   * @param onNetworkResponse An optional callback for network responses.
   * @returns The loaded object, or `undefined` if no object is available.
   */
  public static async loadObjectByID<T>(
    id: string,
    cipherKey: CipherKey,
    onNetworkResponse?: (data: unknown) => void | Promise<void>
  ): Promise<T | undefined> {
    try {
      if (!this.cipherKeyCache.has(id))
        void this.cipherKeyCache.set(id, cipherKey)
      //
      return (await loadObject(
        (this.storageURL + id) as URLString,
        cipherKey,
        false,
        onNetworkResponse
      )) as T
    } catch (cause) {
      throw unknownError(cause, 'Explorer.loadObjectByID()')
    }
  }

  /**
   * Encrypts and stores an object using its identifier and cipher key.
   *
   * Caches the cipher key if the identifier has not been encountered before.
   *
   * @typeParam T The type of the object to store.
   * @param id The identifier of the object to store.
   * @param object The object to encrypt and store.
   * @param cipherKey The key used to encrypt the object.
   */
  public static async storeObjectByID<T>(
    id: string,
    object: T,
    cipherKey: CipherKey
  ): Promise<void> {
    try {
      if (!this.cipherKeyCache.has(id))
        void this.cipherKeyCache.set(id, cipherKey)
      //
      return void (await storeObject(
        (this.storageURL + id) as URLString,
        object,
        cipherKey
      ))
    } catch (cause) {
      throw unknownError(cause, 'Explorer.storeObjectByID()')
    }
  }

  /**
   * Deletes a persisted object using its identifier.
   *
   * @param id The identifier of the object to delete.
   */
  public static async deleteObjectByID(id: string): Promise<void> {
    try {
      void (await deleteObject((this.storageURL + id) as URLString))
      return void (await this.loadRecentEntries()).delete(id)
    } catch (cause) {
      throw unknownError(cause, 'Explorer.deleteObjectByID()')
    }
  }

  /**
   * Schedules the application of a synchronized Explorer delta.
   *
   * Recognized deltas are forwarded to their corresponding entries list.
   * Invalid or unrecognized delta types are ignored.
   *
   * Processing is scheduled in a microtask and is not awaited by the caller.
   *
   * @param data The delta to apply.
   */
  public static apply(data: unknown): void {
    return void queueMicrotask(async () => {
      try {
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
      } catch (cause) {
        throw unknownError(cause, 'Explorer.apply()')
      }
    })
  }

  //* ███████╗██╗   ██╗███████╗███╗   ██╗████████╗   ████████╗ █████╗ ██████╗  ██████╗ ███████╗████████╗
  //* ██╔════╝██║   ██║██╔════╝████╗  ██║╚══██╔══╝   ╚══██╔══╝██╔══██╗██╔════╝ ██╔════╝╚══██╔══╝
  //* █████╗  ██║   ██║█████╗  ██╔██╗ ██║   ██║         ██║   ███████║██████╔╝██║  ███╗█████╗     ██║
  //* ██╔══╝  ╚██╗ ██╔╝██╔══╝  ██║╚██╗██║   ██║         ██║   ██╔══██║██╔══██╗██║   ██║██╔══╝     ██║
  //* ███████╗ ╚████╔╝ ███████╗██║ ╚████║   ██║         ██║   ██║  ██║██║  ██║╚██████╔╝███████╗   ██║
  //* ╚══════╝  ╚═══╝  ╚══════╝╚═╝  ╚═══╝   ╚═╝         ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝

  /**
   * Registers an event listener for the specified event type.
   *
   * @param type The event type.
   * @param listener The event listener, or `null`.
   * @param options The event listener options.
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
   * Removes an event listener previously registered with
   * {@link addEventListener}.
   *
   * @param type The event type.
   * @param listener The event listener to remove, or `null`.
   * @param options The event listener options.
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
   * Dispatches an event to the registered listeners.
   *
   * @param type The event type.
   * @param detail The value exposed through `CustomEvent.detail`.
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

  /**
   * Determines whether a value has the basic structure of an Explorer delta.
   *
   * @param data The value to inspect.
   * @returns Whether the value has a string discriminator.
   */
  private static isExplorerDelta(data: unknown): data is ExplorerDelta {
    return Array.isArray(data) && typeof data[0] === 'string'
  }

  private static recentEntries?: RecentEntries

  /**
   * Loads or returns the cached recent entries list.
   *
   * Derives the list identifier and cipher key from the database secret
   * and merges subsequent network responses into the loaded state.
   *
   * @returns The recent entries list.
   * @throws {ExplorerError} If the database is not authenticated.
   */
  private static async loadRecentEntries(): Promise<RecentEntries> {
    try {
      if (!this.isAuthenticated) throw new ExplorerError('NOT_AUTHENTICATED')

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
    } catch (cause) {
      throw unknownError(cause, 'Explorer.loadRecentEntries()')
    }
  }

  private static credentialEntries?: CredentialEntries

  /**
   * Loads or returns the cached credential entries list.
   *
   * Derives the list identifier and cipher key from the database secret
   * and merges subsequent network responses into the loaded state.
   *
   * @returns The credential entries list.
   * @throws {ExplorerError} If the database is not authenticated.
   */
  private static async loadCredentialEntries(): Promise<CredentialEntries> {
    try {
      if (!this.isAuthenticated) throw new ExplorerError('NOT_AUTHENTICATED')

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
    } catch (cause) {
      throw unknownError(cause, 'Explorer.loadCredentialEntries()')
    }
  }
}
